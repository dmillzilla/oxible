// SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use oxible::{
    FileKind, config, fix, lint_source, output,
    rules::RULES,
    runner::{self, CheckSettings, Exclusions, Report},
};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Oxible — Ansible checks, forged in Rust",
    long_about = "A native Rust Ansible linter, with safe fixes and an editor language server.\nChecks run without Python or Ansible. Compatibility boundaries are documented in README."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List implemented rules in each progressive profile
    Profiles,
    /// List supported category tags and their rule families
    Tags,
    /// Check playbooks, role tasks, and handlers
    Check(Box<CheckArgs>),
    /// List implemented rules (descriptions identify opt-in checks)
    Rules {
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Run the Language Server Protocol over stdin/stdout
    Server,
}

#[derive(Args)]
struct CheckArgs {
    #[arg(short = 'L', long, conflicts_with_all = ["list_tags", "list_profiles"])]
    list_rules: bool,
    #[arg(short = 'T', long, conflicts_with_all = ["list_rules", "list_profiles"])]
    list_tags: bool,
    #[arg(short = 'P', long, conflicts_with_all = ["list_rules", "list_tags"])]
    list_profiles: bool,
    /// Builtin rules remain enabled; custom Python rule execution is unsupported
    #[arg(short = 'R')]
    use_default_rules: bool,
    #[arg(short = 'r', long = "rules-dir")]
    rulesdir: Vec<PathBuf>,
    /// Files/directories, or - for stdin; directory scans honor .gitignore
    paths: Vec<PathBuf>,
    #[arg(short = 'f', long, value_enum, default_value = "text")]
    format: Format,
    /// Restrict checks to comma-separated IDs; all includes opt-in rules
    #[arg(short = 't', long, alias = "tags")]
    select: Vec<String>,
    /// Skip rule IDs; syntax and I/O errors cannot be skipped
    #[arg(short = 'x', long, alias = "skip-list", value_delimiter = ',')]
    skip: Vec<String>,
    /// Enable additional opt-in rule IDs without replacing the default checks
    #[arg(long, alias = "enable-list")]
    enable: Vec<String>,
    /// Report selected rules without failing (unless --strict)
    #[arg(short = 'w', long, alias = "warn-list", value_delimiter = ',')]
    warn: Vec<String>,
    /// Exclude a path/glob relative to the configuration directory (or cwd)
    #[arg(long, num_args = 1..)]
    exclude: Vec<String>,
    #[arg(short = 'c', long, alias = "config-file")]
    config: Option<PathBuf>,
    /// Select the project root and starting point for lint config discovery
    #[arg(long)]
    project_dir: Option<PathBuf>,
    /// Use an explicit yamllint policy
    #[arg(long)]
    yamllint_file: Option<PathBuf>,
    /// Write SARIF alongside the selected stdout format
    #[arg(long)]
    sarif_file: Option<PathBuf>,
    /// Use an upstream progressive rule profile
    #[arg(long, value_parser = parse_profile)]
    profile: Option<String>,
    /// Load filename/rule baseline entries
    #[arg(short = 'i', long)]
    ignore_file: Option<PathBuf>,
    /// Write current findings to .ansible-lint-ignore in the working directory
    #[arg(long)]
    generate_ignore: bool,
    /// Skip installing role/collection requirements
    #[arg(long, overrides_with_all = ["offline", "no_offline"])]
    offline: bool,
    /// Install project requirements using native data transports
    #[arg(long, overrides_with_all = ["offline", "no_offline"])]
    no_offline: bool,
    /// Disable terminal colors
    #[arg(long, overrides_with_all = ["nocolor", "force_color"])]
    nocolor: bool,
    #[arg(long, overrides_with_all = ["nocolor", "force_color"])]
    force_color: bool,
    /// Use absolute paths, matching the pinned compatibility flag
    #[arg(long)]
    show_relpath: bool,
    #[arg(short = 'q', action = clap::ArgAction::Count)]
    quiet: u8,
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbosity: u8,
    #[arg(long, value_enum, default_value = "auto")]
    kind: FileKind,
    /// Apply only reviewed safe edits and recheck the resulting files
    #[arg(long, conflicts_with = "diff", num_args = 0..=1, default_missing_value = "__default__", value_delimiter = ',')]
    fix: Option<Vec<String>>,
    /// Preview safe edits as a unified diff without modifying source
    #[arg(long)]
    diff: bool,
    /// Disable the content-addressed result cache
    #[arg(long)]
    no_cache: bool,
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    /// Write machine-readable static-analysis coverage alongside any lint format
    #[arg(long)]
    analysis_report: Option<PathBuf>,
    /// Make warn_list/--warn findings fail too
    #[arg(short = 's', long)]
    strict: bool,
    /// Validate play structure and resolve module names using native Rust
    #[arg(long, alias = "syntax-check")]
    ansible_syntax_check: bool,
    /// Disable module-resolution validation for isolated policy-rule analysis
    #[arg(long)]
    no_syntax_check: bool,
    /// Disable traversal of literal includes and locally available roles
    #[arg(long)]
    no_follow_imports: bool,
    /// Follow literal task/playbook imports and locally available roles
    #[arg(long)]
    follow_imports: bool,
    /// Classify and label stdin as this path (requires a single - input)
    #[arg(long)]
    stdin_filename: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Brief,
    Full,
    Md,
    Quiet,
    Pep8,
    Json,
    Sarif,
    Codeclimate,
}

fn parse_profile(value: &str) -> Result<String, String> {
    config::validate_profile(value)?;
    Ok(value.to_owned())
}

struct RunError {
    message: String,
    code: u8,
}
impl From<String> for RunError {
    fn from(message: String) -> Self {
        Self { message, code: 2 }
    }
}
impl From<&str> for RunError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

fn run(cli: Cli, compatible: bool) -> Result<u8, RunError> {
    if matches!(cli.command, Command::Server) {
        return oxible::lsp::run().map_err(Into::into);
    }
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    let mut trailing_newline = true;
    let code = match cli.command {
        Command::Profiles => {
            serde_json::to_writer_pretty(&mut writer, &config::profiles())
                .map_err(|e| e.to_string())?;
            0
        }
        Command::Tags => {
            serde_json::to_writer_pretty(&mut writer, &config::tags())
                .map_err(|e| e.to_string())?;
            0
        }
        Command::Rules { format } => {
            match format {
                Format::Json => serde_json::to_writer_pretty(&mut writer, RULES)
                    .map_err(|error| error.to_string())?,
                Format::Sarif | Format::Codeclimate => {
                    return Err("SARIF/Code Climate are available for `check`, not `rules`".into());
                }
                Format::Text
                | Format::Brief
                | Format::Full
                | Format::Md
                | Format::Quiet
                | Format::Pep8 => {
                    for rule in RULES {
                        writeln!(writer, "{:<27} {}", rule.id, rule.description)
                            .map_err(|error| error.to_string())?;
                    }
                }
            }
            0
        }
        Command::Check(mut args) => {
            if !args.rulesdir.is_empty() {
                return Err(RunError { message: "Custom Python rule directories are unsupported by native Rust checking; requested custom policy was not executed".into(), code: if compatible { 3 } else { 2 } });
            }
            if !compatible {
                args.select = args
                    .select
                    .iter()
                    .flat_map(|value| value.split(',').map(str::to_owned))
                    .collect();
                args.enable = args
                    .enable
                    .iter()
                    .flat_map(|value| value.split(',').map(str::to_owned))
                    .collect();
                for selectors in [&args.select, &args.skip, &args.enable, &args.warn] {
                    config::validate_selectors(selectors)?;
                }
            }
            if args.diff && args.format != Format::Text {
                return Err("--diff produces text; use it without --format json/sarif".into());
            }
            let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
            let project = args.project_dir.as_ref().map(|p| cwd.join(p));
            if let Some(path) = &project
                && !path.is_dir()
            {
                return Err(RunError {
                    message: format!("Invalid project_dir {}", path.display()),
                    code: if compatible { 1 } else { 2 },
                });
            }
            let project = project
                .map(std::fs::canonicalize)
                .transpose()
                .map_err(|e| e.to_string())?;
            let mut config =
                config::load_with_project(args.config.as_deref(), &cwd, project.as_deref())
                    .map_err(|message| RunError {
                        message,
                        code: if compatible { 3 } else { 2 },
                    })?;
            if let Some(path) = &args.yamllint_file {
                let path = cwd.join(path);
                if !compatible || path.is_file() {
                    config.settings.yaml = oxible::yaml_lint::Policy::load(Some(&path), &cwd)?;
                }
            }
            if args.profile.is_some() {
                config.profile = args.profile;
            }
            if let Some(profile) = config.profile.as_deref() {
                oxible::config::validate_profile(profile)?;
            }
            for warning in &config.warnings {
                eprintln!("oxible: warning: {warning}");
            }
            let mut options = config.lint_options();
            options.pinned_selectors = compatible;
            options.kind = args.kind;
            options.select.extend(args.select);
            options.skip.extend(args.skip);
            if !args.warn.is_empty() && !config.warn_list_explicit {
                options.warn.clear();
            }
            options.warn.extend(args.warn);
            options.enable.extend(args.enable);
            if args.list_rules || args.list_tags || args.list_profiles {
                let listing = if args.list_profiles {
                    oxible::listing::profiles()
                } else if args.list_tags {
                    oxible::listing::tags()
                } else {
                    if !matches!(
                        args.format,
                        Format::Text | Format::Brief | Format::Full | Format::Md
                    ) {
                        return Err("With --list-rules, only brief, full and md output formats are supported".into());
                    }
                    oxible::listing::rules()
                };
                writeln!(writer, "{listing}").map_err(|error| error.to_string())?;
                writer.flush().map_err(|error| error.to_string())?;
                return Ok(0);
            }
            if let Some(path) = args.ignore_file {
                options.baseline = if compatible && !path.try_exists().map_err(|e| e.to_string())? {
                    Vec::new()
                } else {
                    config::load_ignore(Some(&path), &cwd)?
                };
            }
            let mut patterns = config.exclude_paths;
            let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
            patterns.extend(
                args.exclude
                    .into_iter()
                    .map(|p| cwd.join(p).to_string_lossy().into_owned()),
            );
            let exclusions = Exclusions::new(&patterns, &config.base)?;
            let stdin = args.paths.iter().any(|path| path.as_os_str() == "-");
            // The pin currently gives a nonempty file write_list precedence
            // over CLI values. Keep the observed behavior under differential
            // coverage, even though its CLI help describes the reverse.
            let write_list = if !config.write_list.is_empty() {
                config.write_list
            } else {
                args.fix.clone().unwrap_or_default()
            };
            let mut write_list: Vec<_> = write_list
                .into_iter()
                .filter(|value| value != "__default__")
                .collect();
            if write_list.is_empty() && args.fix.is_some() {
                write_list.push("all".into());
            }
            for magic in ["all", "none"] {
                if write_list.len() > 1 && write_list.iter().any(|value| value == magic) {
                    return Err(RunError {
                        message: format!("{magic:?} cannot be combined with other --fix values"),
                        code: if compatible { 3 } else { 2 },
                    });
                }
            }
            fix::validate_write_list(&write_list, &options).map_err(|message| RunError {
                message,
                code: if compatible { 3 } else { 2 },
            })?;
            let offline = if args.offline {
                true
            } else if args.no_offline {
                false
            } else {
                config.offline.unwrap_or(!compatible)
            };
            let project_root = options.project_dir.as_deref().unwrap_or(&cwd);
            let preparation = oxible::prepare::environment(project_root, &options, offline)
                .map_err(|message| RunError {
                    message,
                    code: if compatible { 1 } else { 2 },
                })?;
            if preparation.changed || preparation.cache_dir.is_some() {
                options.settings.collection_index =
                    std::sync::Arc::new(oxible::collections::Index::try_load_with_cache(
                        project_root,
                        &cwd,
                        preparation.cache_dir.as_deref(),
                        !offline,
                    )?);
            }
            if compatible {
                let incompatible = options.settings.yaml.formatter_incompatibilities();
                if !incompatible.is_empty() {
                    let message = format!(
                        "Custom yamllint policy conflicts with pinned formatter requirements:\n  - {}. Fix mode is unavailable",
                        incompatible.join("\n  - ")
                    );
                    if !write_list.is_empty() && write_list != ["none"] {
                        return Err(RunError { message, code: 3 });
                    }
                    eprintln!("oxible: warning: {message}");
                }
            }
            let fix_enabled = !write_list.is_empty()
                && write_list != ["none"]
                && !(compatible && options.skip.iter().any(|selector| selector == "yaml"));
            let fix_selection = fix::Selection {
                include: if args.diff && write_list.is_empty() {
                    vec!["all".into()]
                } else {
                    write_list
                },
                exclude: config.write_exclude_list,
            };
            options.generate_fixes = fix_enabled || args.diff || args.format == Format::Json;
            let settings = CheckSettings {
                yaml_format: compatible && fix_enabled,
                fix_selection,
                explicit_paths: compatible && !args.paths.is_empty(),
                fix: fix_enabled,
                diff: args.diff,
                cache_dir: if args.no_cache {
                    None
                } else {
                    Some(
                        args.cache_dir
                            .unwrap_or_else(|| config.base.join(".oxible_cache")),
                    )
                },
                ansible_syntax_check: !args.no_syntax_check || args.ansible_syntax_check,
                follow_imports: !args.no_follow_imports || args.follow_imports,
            };
            let report = if stdin {
                if args.paths.len() != 1 {
                    return Err("Stdin (-) cannot be combined with filesystem paths".into());
                }
                if fix_enabled {
                    return Err("Use --diff for stdin fixes; --fix requires a file".into());
                }
                if args.stdin_filename.is_none() && options.kind == FileKind::Auto {
                    options.kind = FileKind::Playbook;
                }
                let path = args
                    .stdin_filename
                    .unwrap_or_else(|| PathBuf::from("stdin.yml"));
                let path = if path.is_absolute() {
                    path
                } else {
                    std::env::current_dir()
                        .map_err(|error| error.to_string())?
                        .join(path)
                };
                let mut source = String::new();
                io::stdin()
                    .read_to_string(&mut source)
                    .map_err(|error| error.to_string())?;
                let mut result = lint_source(&path, &source, &options);
                if settings.ansible_syntax_check {
                    oxible::syntax::validate(&path, &source, &options, &mut result);
                }
                let mut report = Report {
                    files_encountered: 1,
                    files_checked: usize::from(result.checked),
                    files_skipped: usize::from(!result.checked),
                    diagnostics: result.diagnostics,
                    analysis: result.analysis,
                    ..Report::default()
                };
                if args.diff {
                    let edits = fix::plan_selected(&report.diagnostics, &settings.fix_selection);
                    if !edits.is_empty() {
                        let replacement = fix::apply(&source, &edits)?;
                        report.diffs.push((
                            path.display().to_string(),
                            similar::TextDiff::from_lines(&source, &replacement)
                                .unified_diff()
                                .header("a/stdin", "b/stdin")
                                .to_string(),
                        ));
                    }
                }
                report
            } else {
                if args.stdin_filename.is_some() {
                    return Err("--stdin-filename requires stdin (-)".into());
                }
                let paths = if args.paths.is_empty() {
                    vec![PathBuf::from(".")]
                } else {
                    args.paths
                };
                runner::check_with(&paths, &options, &exclusions, &settings)
            };
            if args.generate_ignore {
                config::generate_ignore(&report, &cwd)?;
            }
            let strict_failure = (args.strict || config.strict) && !report.diagnostics.is_empty();
            let quiet = args.quiet > 0 || config.quiet;
            let relative_paths = config.display_relative_path && !args.show_relpath;
            let sarif = if args.format == Format::Sarif
                || args.sarif_file.is_some()
                || config.sarif_file.is_some()
            {
                Some(if compatible {
                    output::sarif_compatible(&report, &cwd)?
                } else {
                    output::sarif(&report)
                })
            } else {
                None
            };
            if let Some(path) = &args.analysis_report {
                let file = std::fs::File::create(path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                let mut writer = io::BufWriter::new(file);
                serde_json::to_writer_pretty(&mut writer, &report.analysis)
                    .map_err(|error| error.to_string())?;
                writer.flush().map_err(|error| error.to_string())?;
            }
            if let Some(path) = args.sarif_file.as_ref().or(config.sarif_file.as_ref()) {
                let file = std::fs::File::create(path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                let mut writer = io::BufWriter::new(file);
                if compatible {
                    serde_json::to_writer(&mut writer, sarif.as_ref().expect("SARIF sidecar"))
                } else {
                    serde_json::to_writer_pretty(
                        &mut writer,
                        sarif.as_ref().expect("SARIF sidecar"),
                    )
                }
                .map_err(|error| error.to_string())?;
                writer.flush().map_err(|error| error.to_string())?;
            }
            let mut notices = std::collections::BTreeSet::new();
            for record in report.analysis.iter().filter(|r| r.state.incomplete()) {
                let key = (
                    &record.path,
                    &record.scope,
                    &record.subject,
                    record.state,
                    &record.reason,
                );
                if notices.insert(key) {
                    eprintln!("oxible: {}", record.notice());
                }
            }
            match args.format {
                Format::Json => serde_json::to_writer_pretty(&mut writer, &report)
                    .map_err(|error| error.to_string())?,
                Format::Sarif => {
                    if compatible {
                        serde_json::to_writer(&mut writer, sarif.as_ref().expect("SARIF stdout"))
                    } else {
                        serde_json::to_writer_pretty(
                            &mut writer,
                            sarif.as_ref().expect("SARIF stdout"),
                        )
                    }
                    .map_err(|error| error.to_string())?;
                }
                Format::Codeclimate => serde_json::to_writer(
                    &mut writer,
                    &output::codeclimate_with_paths(&report, relative_paths),
                )
                .map_err(|error| error.to_string())?,
                Format::Brief | Format::Full | Format::Md | Format::Quiet | Format::Pep8 => {
                    trailing_newline = false;
                    let colored = output::use_color(args.force_color, args.nocolor);
                    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
                    // Upstream text output groups baseline entries first.
                    for ignored in [true, false] {
                        for item in report
                            .diagnostics
                            .iter()
                            .filter(|item| item.ignored == ignored)
                        {
                            let path = std::path::Path::new(&item.path);
                            // Pinned Lintable names are already relative to cwd;
                            // disabling formatter relativization preserves them.
                            let path = path.strip_prefix(&cwd).unwrap_or(path);
                            let position = if item.column > 0 && !item.rule.starts_with("yaml[") {
                                format!("{}:{}", item.line, item.column)
                            } else {
                                item.line.to_string()
                            };
                            let warning = if item.warning_level() {
                                " (warning)"
                            } else {
                                ""
                            };
                            let text = match args.format {
                                Format::Quiet => format!(
                                    "{} {}:{position}\n",
                                    item.rule.split('[').next().unwrap_or(&item.rule),
                                    path.display()
                                ),
                                Format::Pep8 => format!(
                                    "{}:{position}: {}[/]{}{warning}\n",
                                    path.display(),
                                    item.rule,
                                    if quiet {
                                        String::new()
                                    } else {
                                        format!(": {}", item.message)
                                    }
                                ),
                                _ => format!(
                                    "{}: {}{warning}{}\n{}:{position}{}\n\n",
                                    item.rule,
                                    item.message,
                                    if ignored { " # ignored" } else { "" },
                                    path.display(),
                                    if item.details.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" {}", item.details)
                                    }
                                ),
                            };
                            let text = if colored {
                                output::colored_text(
                                    item,
                                    &path.display().to_string(),
                                    &position,
                                    quiet,
                                    match args.format {
                                        Format::Quiet => "quiet",
                                        Format::Pep8 => "pep8",
                                        _ => "default",
                                    },
                                )
                            } else {
                                text
                            };
                            write!(writer, "{text}").map_err(|error| error.to_string())?;
                        }
                    }
                }
                Format::Text => {
                    if args.diff {
                        for (_, diff) in &report.diffs {
                            write!(writer, "{diff}").map_err(|error| error.to_string())?;
                        }
                    } else {
                        let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
                        for item in &report.diagnostics {
                            let path = std::path::Path::new(&item.path);
                            writeln!(
                                writer,
                                "{}:{}:{}: {}: {}{}",
                                path.strip_prefix(&cwd).unwrap_or(path).display(),
                                item.line,
                                item.column,
                                item.rule,
                                item.message,
                                if item.warn_only {
                                    " (warning only)"
                                } else {
                                    ""
                                }
                            )
                            .map_err(|error| error.to_string())?;
                        }
                    }
                    eprintln!(
                        "{} finding(s) in {} Ansible file(s); {} other YAML file(s) skipped; {} cached; {} fix(es) applied",
                        report.diagnostics.len(),
                        report.files_checked,
                        report.files_skipped,
                        report.files_cached,
                        report.fixes_applied
                    );
                }
            }
            let code = if strict_failure {
                report.exit_code().max(1)
            } else {
                report.exit_code()
            };
            if compatible
                && report.files_fixed > 0
                && !report
                    .diagnostics
                    .iter()
                    .any(|item| item.severity == oxible::Severity::Error || !item.warn_only)
            {
                8
            } else if compatible && code == 0 && report.files_encountered == 0 {
                5
            } else {
                code
            }
        }
        Command::Server => unreachable!(),
    };
    if trailing_newline {
        writeln!(writer).map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())?;
    Ok(code)
}

fn main() -> ExitCode {
    let mut args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        let command = Cli::command();
        let mut help = command.find_subcommand("check").expect("check command").clone()
            .name("oxible").about("Oxible — Ansible checks, forged in Rust")
            .after_help("Additional commands: check, rules, profiles, tags, server.\nChecking is native Rust. Online mode prepares requirements; --offline skips downloads.\nDocumented compatibility boundaries: README.md and PARITY_PLAN.md.");
        if help.print_long_help().is_err() {
            return ExitCode::FAILURE;
        }
        println!();
        return ExitCode::SUCCESS;
    }
    let implicit = args.get(1).is_none_or(|arg| {
        !matches!(
            arg.to_str(),
            Some(
                "check"
                    | "rules"
                    | "profiles"
                    | "tags"
                    | "server"
                    | "compat"
                    | "help"
                    | "--help"
                    | "-h"
                    | "--version"
                    | "-V"
            )
        )
    });
    if implicit {
        args.insert(1, "check".into());
    }
    let matches = Cli::command().get_matches_from(args);
    let fix_path = matches.subcommand_matches("check").and_then(|matches| {
        let first_path = matches
            .indices_of("paths")
            .and_then(|mut indices| indices.next())
            .unwrap_or(usize::MAX);
        matches
            .get_many::<String>("fix")?
            .zip(matches.indices_of("fix")?)
            .enumerate()
            .find(|(_, (value, index))| {
                *index < first_path
                    && value.as_str() != "__default__"
                    && std::path::Path::new(value.as_str()).exists()
            })
            .map(|(index, (value, _))| (index, PathBuf::from(value)))
    });
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    if let Some((index, path)) = fix_path
        && let Command::Check(args) = &mut cli.command
    {
        args.paths.insert(0, path);
        args.fix.as_mut().expect("fix values present")[index] = "__default__".into();
    }
    if implicit && let Command::Check(args) = &mut cli.command {
        args.format = match args.format {
            Format::Json => Format::Codeclimate,
            Format::Text => Format::Brief,
            format => format,
        };
    }
    match run(cli, implicit) {
        Ok(code) => ExitCode::from(if implicit && code == 1 { 2 } else { code }),
        Err(error) => {
            eprintln!("oxible: {}", error.message);
            ExitCode::from(error.code)
        }
    }
}
