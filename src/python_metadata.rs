// SPDX-License-Identifier: GPL-3.0-or-later
//! Read declarative plugin metadata using Rust's Python parser. Never execute it.
use ruff_python_ast::{
    Expr, Number, Stmt, UnaryOp,
    visitor::{Visitor, walk_expr, walk_stmt},
};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

type Bindings = BTreeMap<String, Option<Value>>;
const FIELDS: &[&str] = &[
    "argument_spec",
    "required_one_of",
    "required_together",
    "required_if",
    "required_by",
    "mutually_exclusive",
    "add_file_common_args",
];

#[derive(Clone, Debug, Default)]
pub(crate) struct File {
    pub documents: BTreeMap<String, String>,
    pub runtime: Value,
    pub has_main: bool,
    exports: Bindings,
}

fn name(expression: &Expr) -> Option<&str> {
    expression.as_name_expr().map(|e| e.id.as_str())
}
fn call_name(expression: &Expr) -> Option<&str> {
    match expression {
        Expr::Name(e) => Some(e.id.as_str()),
        Expr::Attribute(e) => Some(e.attr.as_str()),
        _ => None,
    }
}
fn qualified(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Name(e) => Some(e.id.to_string()),
        Expr::Attribute(e) => Some(format!("{}.{}", qualified(&e.value)?, e.attr)),
        _ => None,
    }
}

/// A bounded literal reader, not a Python evaluator. Unknown operations fail.
struct Literals {
    remaining: usize,
}
impl Literals {
    fn new() -> Self {
        Self { remaining: 100_000 }
    }
    fn value(&mut self, expression: &Expr, bindings: &Bindings, depth: usize) -> Option<Value> {
        if depth > 48 || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let mut nested = |e| self.value(e, bindings, depth + 1);
        match expression {
            Expr::StringLiteral(e) => Some(Value::String(e.value.to_str().to_owned())),
            Expr::BooleanLiteral(e) => Some(Value::Bool(e.value)),
            Expr::NoneLiteral(_) => Some(Value::Null),
            Expr::NumberLiteral(e) => match &e.value {
                Number::Int(n) => n.as_i64().map(Value::from),
                Number::Float(n) => serde_json::Number::from_f64(*n).map(Value::Number),
                _ => None,
            },
            Expr::Name(e) => match bindings.get(e.id.as_str()) {
                Some(value) => value.clone(),
                None if matches!(
                    e.id.as_str(),
                    "str" | "int" | "float" | "bool" | "dict" | "list" | "bytes"
                ) =>
                {
                    Some(Value::String(e.id.to_string()))
                }
                _ => None,
            },
            Expr::Attribute(e) => nested(&e.value)?.as_object()?.get(e.attr.as_str()).cloned(),
            Expr::List(e) => e
                .elts
                .iter()
                .map(&mut nested)
                .collect::<Option<Vec<_>>>()
                .map(Value::Array),
            Expr::Tuple(e) => e
                .elts
                .iter()
                .map(&mut nested)
                .collect::<Option<Vec<_>>>()
                .map(Value::Array),
            Expr::Set(e) => e
                .elts
                .iter()
                .map(&mut nested)
                .collect::<Option<Vec<_>>>()
                .map(Value::Array),
            Expr::Dict(e) => {
                let mut result = Map::new();
                for item in &e.items {
                    let value = nested(&item.value)?;
                    if let Some(key) = &item.key {
                        result.insert(nested(key)?.as_str()?.to_owned(), value);
                    } else {
                        result.extend(value.as_object()?.clone());
                    }
                }
                Some(Value::Object(result))
            }
            Expr::Call(e) if name(&e.func) == Some("dict") && !bindings.contains_key("dict") => {
                let mut result = Map::new();
                if e.arguments.args.len() > 1 {
                    return None;
                }
                if let Some(arg) = e.arguments.args.first() {
                    result.extend(nested(arg)?.as_object()?.clone());
                }
                for keyword in &e.arguments.keywords {
                    let value = nested(&keyword.value)?;
                    if let Some(key) = &keyword.arg {
                        result.insert(key.to_string(), value);
                    } else {
                        result.extend(value.as_object()?.clone());
                    }
                }
                Some(Value::Object(result))
            }
            Expr::UnaryOp(e) => {
                let value = nested(&e.operand)?;
                match e.op {
                    UnaryOp::UAdd => value.is_number().then_some(value),
                    UnaryOp::USub => {
                        if let Some(n) = value.as_i64() {
                            n.checked_neg().map(Value::from)
                        } else {
                            serde_json::Number::from_f64(-value.as_f64()?).map(Value::Number)
                        }
                    }
                    _ => None,
                }
            }
            Expr::BinOp(e) => {
                let left = nested(&e.left)?;
                let right = nested(&e.right)?;
                match (e.op, left, right) {
                    (ruff_python_ast::Operator::Add, Value::Array(mut a), Value::Array(b)) => {
                        a.extend(b);
                        Some(Value::Array(a))
                    }
                    (ruff_python_ast::Operator::Add, Value::String(mut a), Value::String(b))
                        if a.len() + b.len() <= 256 * 1024 =>
                    {
                        a.push_str(&b);
                        Some(Value::String(a))
                    }
                    (ruff_python_ast::Operator::BitOr, Value::Object(mut a), Value::Object(b)) => {
                        a.extend(b);
                        Some(Value::Object(a))
                    }
                    _ => None,
                }
            }
            Expr::Call(e) if e.arguments.is_empty() => bindings
                .get(&format!("$factory:{}", qualified(&e.func)?))
                .cloned()
                .flatten(),
            _ => None,
        }
    }
}

fn invalidate_mutable(bindings: &mut Bindings) {
    for (name, value) in bindings.iter_mut() {
        // These are immutable analysis summaries, not Python variables.
        if name.starts_with('$') {
            continue;
        }
        if value
            .as_ref()
            .is_some_and(|v| v.is_object() || v.is_array())
        {
            *value = None;
        }
    }
}
struct Writes<'a>(&'a mut Bindings);
impl<'a> Visitor<'a> for Writes<'_> {
    fn visit_stmt(&mut self, statement: &'a Stmt) {
        match statement {
            Stmt::Assign(e) => {
                for target in &e.targets {
                    bind(target, None, self.0);
                }
                self.visit_expr(&e.value);
            }
            Stmt::AnnAssign(e) => {
                bind(&e.target, None, self.0);
                if let Some(value) = &e.value {
                    self.visit_expr(value);
                }
            }
            Stmt::AugAssign(e) => bind(&e.target, None, self.0),
            Stmt::FunctionDef(e) => {
                self.0.insert(e.name.to_string(), None);
            }
            Stmt::ClassDef(e) => {
                self.0.insert(e.name.to_string(), None);
            }
            Stmt::Import(_) | Stmt::ImportFrom(_) => assignment(statement, self.0),
            _ => walk_stmt(self, statement),
        }
    }
    fn visit_expr(&mut self, expression: &'a Expr) {
        if matches!(expression, Expr::Call(_)) {
            invalidate_mutable(self.0);
        }
        walk_expr(self, expression);
    }
}
fn bind(target: &Expr, value: Option<Value>, bindings: &mut Bindings) {
    if let Some(name) = name(target) {
        bindings.insert(name.into(), value);
    } else if let Expr::Subscript(target) = target
        && let Some(key) = name(&target.value).map(str::to_owned)
    {
        let item = Literals::new()
            .value(&target.slice, bindings, 0)
            .and_then(|v| v.as_str().map(str::to_owned));
        if let (Some(item), Some(value), Some(Some(Value::Object(map)))) =
            (item, value, bindings.get_mut(&key))
        {
            map.insert(item, value);
        } else {
            bindings.insert(key, None);
        }
    }
}
fn assignment(statement: &Stmt, bindings: &mut Bindings) {
    match statement {
        Stmt::Assign(e) => {
            let value = Literals::new().value(&e.value, bindings, 0);
            if value.is_none() && matches!(e.value.as_ref(), Expr::Call(_)) {
                invalidate_mutable(bindings);
            }
            for target in &e.targets {
                bind(target, value.clone(), bindings);
            }
        }
        Stmt::AnnAssign(e) => {
            let value = e
                .value
                .as_ref()
                .and_then(|e| Literals::new().value(e, bindings, 0));
            bind(&e.target, value, bindings);
        }
        Stmt::AugAssign(e) => bind(&e.target, None, bindings),
        Stmt::Delete(_) => invalidate_mutable(bindings),
        Stmt::Import(e) => {
            for alias in &e.names {
                let name = alias
                    .asname
                    .as_ref()
                    .map(|n| n.as_str())
                    .unwrap_or_else(|| alias.name.as_str().split('.').next().unwrap());
                bindings.insert(name.to_owned(), None);
            }
        }
        Stmt::ImportFrom(e) => {
            for alias in &e.names {
                let name = alias
                    .asname
                    .as_ref()
                    .map(|n| n.as_str())
                    .unwrap_or(alias.name.as_str());
                bindings.insert(name.to_owned(), None);
            }
        }
        Stmt::Expr(statement) => {
            if let Expr::Call(call) = statement.value.as_ref() {
                if let Expr::Attribute(attribute) = call.func.as_ref()
                    && attribute.attr.as_str() == "update"
                    && let Some(target) = name(&attribute.value).map(str::to_owned)
                {
                    let mut update = Map::new();
                    let mut valid = call.arguments.args.len() <= 1;
                    if let Some(arg) = call.arguments.args.first() {
                        if let Some(Value::Object(map)) = Literals::new().value(arg, bindings, 0) {
                            update.extend(map);
                        } else {
                            valid = false;
                        }
                    }
                    for keyword in &call.arguments.keywords {
                        if let Some(value) = Literals::new().value(&keyword.value, bindings, 0) {
                            if let Some(key) = &keyword.arg {
                                update.insert(key.to_string(), value);
                            } else if let Value::Object(map) = value {
                                update.extend(map);
                            } else {
                                valid = false;
                            }
                        } else {
                            valid = false;
                        }
                    }
                    if valid && let Some(Some(Value::Object(map))) = bindings.get_mut(&target) {
                        map.extend(update);
                    } else {
                        bindings.insert(target, None);
                    }
                } else {
                    invalidate_mutable(bindings);
                }
            }
        }
        Stmt::FunctionDef(e) => {
            bindings.insert(e.name.to_string(), None);
        }
        Stmt::ClassDef(e) => {
            bindings.insert(e.name.to_string(), None);
        }
        Stmt::If(_)
        | Stmt::Try(_)
        | Stmt::For(_)
        | Stmt::While(_)
        | Stmt::With(_)
        | Stmt::Match(_) => {
            // Only names potentially written in unknown branches are invalidated.
            walk_stmt(&mut Writes(bindings), statement);
        }
        _ => {}
    }
}

fn partial_option(expression: &Expr, bindings: &Bindings) -> (Value, bool) {
    if let Some(value) = Literals::new().value(expression, bindings, 0) {
        return (value, true);
    }
    let pairs: Vec<(Option<String>, &Expr)> = match expression {
        Expr::Call(e)
            if name(&e.func) == Some("dict")
                && !bindings.contains_key("dict")
                && e.arguments.args.is_empty() =>
        {
            e.arguments
                .keywords
                .iter()
                .map(|k| (k.arg.as_ref().map(ToString::to_string), &k.value))
                .collect()
        }
        Expr::Dict(e) => e
            .items
            .iter()
            .map(|i| {
                (
                    i.key
                        .as_ref()
                        .and_then(|k| Literals::new().value(k, bindings, 0))
                        .and_then(|k| k.as_str().map(str::to_owned)),
                    &i.value,
                )
            })
            .collect(),
        _ => return (serde_json::json!({"type":"raw", "$partial":true}), false),
    };
    let mut fields = Map::new();
    fields.insert("$partial".into(), Value::Bool(true));
    let mut known_aliases = true;
    for (key, value) in pairs {
        let Some(key) = key else {
            return (serde_json::json!({"type":"raw", "$partial":true}), false);
        };
        if let Some(value) = Literals::new().value(value, bindings, 0) {
            fields.insert(key, value);
        } else if key == "type" {
            fields.insert(key, Value::String("raw".into()));
        } else if key == "aliases" {
            known_aliases = false;
        }
    }
    (Value::Object(fields), known_aliases)
}
fn argument_options(expression: &Expr, bindings: &Bindings) -> Option<(Value, bool)> {
    if let Some(mut value) = Literals::new().value(expression, bindings, 0) {
        let complete = value
            .as_object_mut()
            .and_then(|map| map.remove("$unknown_keys"))
            != Some(Value::Bool(true));
        return Some((value, complete));
    }
    let pairs: Vec<(Option<String>, &Expr)> = match expression {
        Expr::Call(e) if name(&e.func) == Some("dict") && !bindings.contains_key("dict") => {
            if !e.arguments.args.is_empty() {
                return None;
            }
            e.arguments
                .keywords
                .iter()
                .map(|k| (k.arg.as_ref().map(ToString::to_string), &k.value))
                .collect()
        }
        Expr::Dict(e) => e
            .items
            .iter()
            .map(|i| {
                (
                    i.key
                        .as_ref()
                        .and_then(|k| Literals::new().value(k, bindings, 0))
                        .and_then(|k| k.as_str().map(str::to_owned)),
                    &i.value,
                )
            })
            .collect(),
        _ => return None,
    };
    let mut options = Map::new();
    let mut complete = true;
    for (name, expression) in pairs {
        if let Some(name) = name {
            let (value, aliases) = partial_option(expression, bindings);
            options.insert(name, value);
            complete &= aliases;
        } else {
            complete = false;
        }
    }
    Some((Value::Object(options), complete))
}
fn module_fields(call: &ruff_python_ast::ExprCall, bindings: &Bindings) -> Value {
    let mut fields = Map::new();
    if let Some((value, complete)) = call
        .arguments
        .args
        .first()
        .and_then(|arg| argument_options(arg, bindings))
    {
        fields.insert("argument_spec".into(), value);
        if !complete {
            fields.insert("$unknown_keys".into(), Value::Bool(true));
        }
    }
    for keyword in &call.arguments.keywords {
        if let Some(key) = keyword.arg.as_ref().map(|n| n.as_str()) {
            if key == "argument_spec" {
                if let Some((options, complete)) = argument_options(&keyword.value, bindings) {
                    fields.insert(key.into(), options);
                    if !complete {
                        fields.insert("$unknown_keys".into(), Value::Bool(true));
                    }
                } else {
                    fields.insert("$partial".into(), Value::Bool(true));
                }
                continue;
            }
            if FIELDS.contains(&key) {
                if let Some(value) = Literals::new().value(&keyword.value, bindings, 0) {
                    fields.insert(key.into(), value);
                } else {
                    fields.insert("$partial".into(), Value::Bool(true));
                    if key == "add_file_common_args" {
                        fields.insert("$unknown_keys".into(), Value::Bool(true));
                    }
                }
            }
        } else if let Some(Value::Object(kwargs)) =
            Literals::new().value(&keyword.value, bindings, 0)
        {
            fields.extend(
                kwargs
                    .into_iter()
                    .filter(|(key, _)| FIELDS.contains(&key.as_str())),
            );
        } else {
            return Value::Null;
        }
    }
    Value::Object(fields)
}
fn referenced_module(expression: &Expr, bindings: &Bindings, depth: usize) -> Option<Value> {
    if depth >= 32 {
        return None;
    }
    match expression {
        Expr::Call(e) => {
            if e.arguments.is_empty()
                && let Some(key) = qualified(&e.func)
                && let Some(Some(value)) = bindings.get(&format!("$module:{key}"))
            {
                return Some(value.clone());
            }
            referenced_module(&e.func, bindings, depth + 1).or_else(|| {
                e.arguments
                    .args
                    .iter()
                    .find_map(|a| referenced_module(a, bindings, depth + 1))
            })
        }
        Expr::Attribute(e) => referenced_module(&e.value, bindings, depth + 1),
        _ => None,
    }
}
fn runtime(body: &[Stmt], globals: &Bindings, constructors: &[String]) -> Value {
    let mut bindings = globals.clone();
    for statement in body {
        let expression = match statement {
            Stmt::Assign(e) => Some(e.value.as_ref()),
            Stmt::AnnAssign(e) => e.value.as_deref(),
            Stmt::Expr(e) => Some(e.value.as_ref()),
            Stmt::Return(e) => e.value.as_deref(),
            _ => None,
        };
        if let Some(Expr::Call(call)) = expression
            && call_name(&call.func).is_some_and(|name| constructors.iter().any(|n| n == name))
        {
            return module_fields(call, &bindings);
        }
        if let Some(value) = expression.and_then(|e| referenced_module(e, &bindings, 0)) {
            return value;
        }
        assignment(statement, &mut bindings);
    }
    Value::Null
}

struct Imports {
    seen: BTreeSet<PathBuf>,
    remaining_bytes: u64,
    files: BTreeMap<PathBuf, File>,
    module_utils: Vec<PathBuf>,
}
pub(crate) fn read(path: &Path, module_utils: &[PathBuf]) -> Option<File> {
    read_inner(
        path,
        &mut Imports {
            seen: BTreeSet::new(),
            remaining_bytes: 8 * 1024 * 1024,
            files: BTreeMap::new(),
            module_utils: module_utils.to_vec(),
        },
        0,
    )
}
fn import_path(
    path: &Path,
    import: &ruff_python_ast::StmtImportFrom,
    module_utils: &[PathBuf],
) -> Option<PathBuf> {
    let module = import.module.as_ref()?.as_str();
    let base = if import.level > 0 {
        let mut base = path.parent()?;
        for _ in 1..import.level {
            base = base.parent()?;
        }
        base.join(module.replace('.', "/"))
    } else if module.starts_with("ansible_collections.")
        && module.contains(".plugins.module_utils.")
    {
        path.ancestors()
            .find(|p| p.file_name().is_some_and(|n| n == "ansible_collections"))?
            .parent()?
            .join(module.replace('.', "/"))
    } else {
        let relative = module.strip_prefix("ansible.module_utils.")?;
        return module_utils
            .iter()
            .flat_map(|root| {
                let base = root.join(relative.replace('.', "/"));
                [base.with_extension("py"), base.join("__init__.py")]
            })
            .find(|p| p.is_file());
    };
    let file = base.with_extension("py");
    if file.is_file() {
        Some(file)
    } else {
        Some(base.join("__init__.py"))
    }
}
fn factory(
    function: &ruff_python_ast::StmtFunctionDef,
    globals: &Bindings,
    class: Option<(&str, &Value)>,
) -> Option<Value> {
    if function.parameters.vararg.is_some() || function.parameters.kwarg.is_some() {
        return None;
    }
    let mut bindings = globals.clone();
    for parameter in function.parameters.iter_non_variadic_params() {
        let value = if let Some((_, value)) = class
            && parameter.parameter.name.as_str() == "cls"
        {
            value.clone()
        } else {
            Literals::new().value(parameter.default.as_deref()?, &bindings, 0)?
        };
        bindings.insert(parameter.parameter.name.to_string(), Some(value));
    }
    for statement in &function.body {
        match statement {
            Stmt::Expr(e) if matches!(e.value.as_ref(), Expr::StringLiteral(_)) => {}
            Stmt::Assign(e) => {
                if Literals::new().value(&e.value, &bindings, 0).is_none() {
                    invalidate_mutable(&mut bindings);
                }
                assignment(statement, &mut bindings)
            }
            Stmt::AnnAssign(e) => {
                if e.value
                    .as_deref()
                    .and_then(|value| Literals::new().value(value, &bindings, 0))
                    .is_none()
                {
                    invalidate_mutable(&mut bindings);
                }
                assignment(statement, &mut bindings)
            }
            Stmt::Return(e) => {
                return Literals::new()
                    .value(e.value.as_deref()?, &bindings, 0)
                    .or_else(|| {
                        let (mut value, complete) =
                            argument_options(e.value.as_deref()?, &bindings)?;
                        if !complete {
                            value
                                .as_object_mut()?
                                .insert("$unknown_keys".into(), Value::Bool(true));
                        }
                        Some(value)
                    });
            }
            _ => return None,
        }
    }
    None
}
fn read_inner(path: &Path, imports: &mut Imports, depth: usize) -> Option<File> {
    if let Some(file) = imports.files.get(path) {
        return Some(file.clone());
    }
    if depth >= 8 || imports.seen.len() >= 64 || !imports.seen.insert(path.to_path_buf()) {
        return None;
    }
    let bytes = fs::metadata(path).ok()?.len();
    imports.remaining_bytes = imports.remaining_bytes.checked_sub(bytes)?;
    if fs::metadata(path).ok()?.len() > 2 * 1024 * 1024 {
        return None;
    }
    let source = fs::read_to_string(path).ok()?;
    let parsed = ruff_python_parser::parse_module(&source).ok()?;
    let body = &parsed.syntax().body;
    let mut globals = Bindings::new();
    let mut constructors = vec!["AnsibleModule".into()];
    let mut result = File::default();
    for statement in body {
        let imported = if let Stmt::ImportFrom(import) = statement
            && !import.names.iter().all(|a| {
                matches!(
                    a.name.as_str(),
                    "AnsibleModule" | "ModuleHelper" | "StateModuleHelper"
                )
            }) {
            import_path(path, import, &imports.module_utils)
                .and_then(|p| read_inner(&p, imports, depth + 1))
                .map(|file| (import, file))
        } else {
            None
        };
        if let Stmt::ImportFrom(import) = statement
            && import
                .module
                .as_ref()
                .is_some_and(|m| m.as_str() == "ansible.module_utils.basic")
        {
            for alias in &import.names {
                if alias.name.as_str() == "AnsibleModule"
                    && let Some(name) = &alias.asname
                {
                    constructors.push(name.to_string());
                }
            }
        }
        if let Stmt::ClassDef(class) = statement
            && class.name.as_str() == "ModuleDocFragment"
        {
            let mut fields = Bindings::new();
            for statement in &class.body {
                assignment(statement, &mut fields);
            }
            result.documents.extend(
                fields
                    .into_iter()
                    .filter_map(|(name, value)| Some((name, value?.as_str()?.to_owned()))),
            );
        }
        // The conventional entrypoint guard does not define module constants.
        if let Stmt::If(statement) = statement
            && let Expr::Compare(compare) = statement.test.as_ref()
            && compare.operands.first().and_then(name) == Some("__name__")
        {
            continue;
        }
        assignment(statement, &mut globals);
        if let Some((import, file)) = imported {
            for alias in &import.names {
                let local = alias
                    .asname
                    .as_ref()
                    .map(|n| n.as_str())
                    .unwrap_or(alias.name.as_str());
                globals.insert(
                    local.to_owned(),
                    file.exports.get(alias.name.as_str()).cloned().flatten(),
                );
                for prefix in ["$factory:", "$module:"] {
                    let key = format!("{prefix}{}", alias.name);
                    if let Some(value) = file.exports.get(&key) {
                        globals.insert(format!("{prefix}{local}"), value.clone());
                    }
                }
            }
        }
        if let Stmt::ClassDef(class) = statement
            && class.decorator_list.is_empty()
        {
            let mut fields = globals.clone();
            let mut own = Map::new();
            let mut module = Value::Null;
            for statement in &class.body {
                if let Stmt::Assign(assign) = statement {
                    if assign.targets.iter().any(|t| name(t) == Some("module"))
                        && let Expr::Call(call) = assign.value.as_ref()
                        && name(&call.func) == Some("dict")
                    {
                        module = module_fields(call, &fields);
                    }
                    assignment(statement, &mut fields);
                    for target in &assign.targets {
                        if let Some(key) = name(target)
                            && let Some(Some(value)) = fields.get(key)
                        {
                            own.insert(key.into(), value.clone());
                        }
                    }
                } else {
                    assignment(statement, &mut fields);
                }
            }
            let class_value = Value::Object(own);
            globals.insert(class.name.to_string(), Some(class_value.clone()));
            for statement in &class.body {
                if let Stmt::FunctionDef(function) = statement
                    && function.decorator_list.iter().any(|d| {
                        matches!(
                            call_name(&d.expression),
                            Some("classmethod" | "staticmethod")
                        )
                    })
                    && let Some(value) = factory(
                        function,
                        &globals,
                        Some((class.name.as_str(), &class_value)),
                    )
                {
                    globals.insert(
                        format!("$factory:{}.{}", class.name, function.name),
                        Some(value),
                    );
                }
            }
            if class.arguments.as_ref().is_some_and(|a| {
                a.args.iter().any(|base| {
                    matches!(call_name(base), Some("StateModuleHelper" | "ModuleHelper"))
                })
            }) && module.is_object()
            {
                globals.insert(format!("$module:{}.execute", class.name), Some(module));
            }
        }
    }
    for statement in body {
        if let Stmt::FunctionDef(function) = statement
            && function.decorator_list.is_empty()
            && let Some(value) = factory(function, &globals, None)
        {
            globals.insert(format!("$factory:{}", function.name), Some(value));
        }
    }
    // Follow only statically identified, zero-argument constructor helpers.
    // This is bounded call-graph analysis; helper code is never executed.
    for _ in 0..4 {
        let mut changed = false;
        for statement in body {
            if let Stmt::FunctionDef(function) = statement
                && function.parameters.is_empty()
                && function.name.as_str() != "main"
            {
                let value = runtime(&function.body, &globals, &constructors);
                if value.is_object()
                    && globals.get(&format!("$module:{}", function.name))
                        != Some(&Some(value.clone()))
                {
                    globals.insert(format!("$module:{}", function.name), Some(value));
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    if let Some(Some(Value::String(document))) = globals.get("DOCUMENTATION") {
        result
            .documents
            .insert("DOCUMENTATION".into(), document.clone());
    }
    if let Some(main) = body.iter().find_map(|statement| match statement {
        Stmt::FunctionDef(f) if f.name.as_str() == "main" => Some(f),
        _ => None,
    }) {
        result.has_main = true;
        if main.parameters.is_empty() {
            result.runtime = runtime(&main.body, &globals, &constructors);
        }
    }
    result.exports = globals;
    imports.files.insert(path.to_path_buf(), result.clone());
    Some(result)
}

pub(crate) fn dictionary(source: &str) -> Option<Value> {
    if source.len() > 256 * 1024 {
        return None;
    }
    if source.starts_with('{') {
        if let Ok(value @ Value::Object(_)) = serde_json::from_str(source) {
            return Some(value);
        }
        let parsed = ruff_python_parser::parse_expression(source).ok()?;
        let value = Literals::new().value(&parsed.syntax().body, &Bindings::new(), 0)?;
        return value.is_object().then_some(value);
    }
    if !source.contains('=') {
        return None;
    }
    let mut quote = None;
    let mut escaped = false;
    let mut field = String::new();
    let mut fields = Vec::new();
    for c in source.trim().chars() {
        if escaped {
            field.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if quote.is_none() && matches!(c, '\'' | '"') {
            quote = Some(c);
        } else if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && matches!(c, ',' | ' ') {
            if !field.is_empty() {
                fields.push(std::mem::take(&mut field));
            }
        } else {
            field.push(c);
        }
    }
    if !field.is_empty() {
        fields.push(field);
    }
    fields
        .into_iter()
        .map(|field| {
            let (key, value) = field.split_once('=')?;
            Some((key.to_owned(), Value::String(value.to_owned())))
        })
        .collect::<Option<Map<_, _>>>()
        .map(Value::Object)
}
