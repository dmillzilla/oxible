// SPDX-License-Identifier: GPL-3.0-or-later
use crate::yaml::{Node, Position};

pub struct SourceMap<'a> {
    pub text: &'a str,
    starts: Vec<usize>,
}
impl<'a> SourceMap<'a> {
    pub fn new(text: &'a str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(index, _)| index + 1));
        Self { text, starts }
    }
    pub fn byte(&self, position: Position) -> Option<usize> {
        let start = *self.starts.get(position.line.checked_sub(1)?)?;
        let line = self.text[start..].split('\n').next()?;
        let column = position.column.checked_sub(1)?;
        let offset = line
            .char_indices()
            .nth(column)
            .map(|(index, _)| index)
            .or_else(|| (line.chars().count() == column).then_some(line.len()))?;
        Some(start + offset)
    }
    pub fn lsp_position(&self, byte: usize) -> Option<(usize, usize)> {
        if byte > self.text.len() || !self.text.is_char_boundary(byte) {
            return None;
        }
        let line = self
            .starts
            .partition_point(|&start| start <= byte)
            .saturating_sub(1);
        Some((
            line,
            self.text[self.starts[line]..byte].encode_utf16().count(),
        ))
    }
    pub fn lsp_byte(&self, line: usize, character: usize) -> Option<usize> {
        let start = *self.starts.get(line)?;
        let text = self.text[start..]
            .split('\n')
            .next()?
            .trim_end_matches('\r');
        let mut utf16 = 0;
        for (offset, ch) in text.char_indices() {
            if utf16 == character {
                return Some(start + offset);
            }
            utf16 += ch.len_utf16();
        }
        (utf16 == character).then_some(start + text.len())
    }
    /// Single-line scalar span, including quotes; multiline edits are withheld.
    pub fn scalar_span(&self, position: Position) -> Option<(usize, usize)> {
        let start = self.byte(position)?;
        let line = self.text[start..].split(['\n', '\r']).next()?;
        let first = line.chars().next()?;
        if matches!(first, '|' | '>') {
            return None;
        }
        if matches!(first, '\'' | '"') {
            let mut chars = line.char_indices().skip(1).peekable();
            let mut escaped = false;
            while let Some((offset, ch)) = chars.next() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if first == '"' && ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == first {
                    if first == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                        chars.next();
                        continue;
                    }
                    return Some((start, start + offset + ch.len_utf8()));
                }
            }
            None
        } else {
            let mut end = line.len();
            let mut previous = ' ';
            for (offset, ch) in line.char_indices() {
                if matches!(ch, ',' | ']' | '}') || (ch == '#' && previous.is_whitespace()) {
                    end = offset;
                    break;
                }
                previous = ch;
            }
            let text = line[..end].trim_end();
            (!text.is_empty()).then_some((start, start + text.len()))
        }
    }
    /// Block plain scalars can contain commas and braces. Match the parser's
    /// complete decoded text instead of treating them as flow delimiters.
    pub fn node_scalar_span(&self, node: &Node) -> Option<(usize, usize)> {
        let start = self.byte(node.position)?;
        if self.text[start..].starts_with(['\'', '"']) {
            return self.scalar_span(node.position);
        }
        let value = node.scalar()?;
        if value.is_empty() || value.contains(['\n', '\r']) {
            return None;
        }
        let end = start.checked_add(value.len())?;
        (self.text.get(start..end) == Some(value)).then_some((start, end))
    }
    /// Raw content lines of a literal/folded scalar. Parser positions point
    /// into content, while alias sites explicitly carry no block source style.
    pub fn block_scalar_span(&self, node: &Node) -> Option<(usize, usize)> {
        if !node.is_block_scalar() || node.scalar()?.trim().is_empty() {
            return None;
        }
        let begin = self.byte(Position {
            line: node.position.line,
            column: 1,
        })?;
        let indent = node.position.column.checked_sub(1)?;
        let mut end = begin;
        for line in self.text[begin..].split_inclusive('\n') {
            let marker = ["---", "..."].iter().any(|marker| {
                line.strip_prefix(marker)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
            });
            if marker
                || (!line.trim().is_empty()
                    && line.bytes().take_while(|ch| *ch == b' ').count() < indent)
            {
                break;
            }
            end += line.len();
        }
        Some((begin, end))
    }
    /// A single-line mapping key, including its quotes but never its colon.
    pub fn key_span(&self, position: Position) -> Option<(usize, usize)> {
        let start = self.byte(position)?;
        let line = self.text[start..].split(['\n', '\r']).next()?;
        let end = if line.starts_with(['\'', '"']) {
            self.scalar_span(position)?.1
        } else {
            start + line.find(':')?
        };
        let key = self.text[start..end].trim_end();
        let after = self.text[end..].trim_start_matches([' ', '\t']);
        if key.is_empty() || !after.starts_with(':') {
            return None;
        }
        Some((start, start + key.len()))
    }
    /// End of a block mapping. Flow mappings require a structural transform.
    pub fn mapping_end(&self, position: Position) -> Option<usize> {
        let start = self.byte(position)?;
        if self.text[start..].starts_with('{') {
            return None;
        }
        let indent = position.column.checked_sub(1)?;
        for &line_start in self.starts.iter().skip(position.line) {
            let line = self.text[line_start..].split(['\n', '\r']).next()?;
            if line.trim().is_empty() {
                continue;
            }
            let leading = line.bytes().take_while(|byte| *byte == b' ').count();
            if leading < indent {
                return Some(line_start);
            }
        }
        Some(self.text.len())
    }
}
