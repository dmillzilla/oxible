// SPDX-License-Identifier: GPL-3.0-or-later
//! Native Python-style policy regex matching. Common patterns stay linear;
//! lookarounds/backreferences use a bounded Rust backtracking engine.
#[derive(Debug)]
pub(crate) enum Pattern {
    Inactive,
    Linear(regex::Regex),
    Backtracking(Box<fancy_regex::Regex>),
}

impl Pattern {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Inactive => "",
            Self::Linear(pattern) => pattern.as_str(),
            Self::Backtracking(pattern) => pattern.as_str(),
        }
    }

    pub fn new(value: &str) -> Result<Self, String> {
        if let Ok(pattern) = regex::Regex::new(value) {
            return Ok(Self::Linear(pattern));
        }
        fancy_regex::RegexBuilder::new(value)
            .backtrack_limit(1_000_000)
            .build()
            .map(|pattern| Self::Backtracking(Box::new(pattern)))
            .map_err(|error| error.to_string())
    }

    pub fn matches_at_start(&self, value: &str) -> Result<bool, String> {
        // Python re.match requires offset zero even without an explicit ^.
        // Do not add a wrapper group which could alter extended-mode comments.
        match self {
            Self::Inactive => Ok(true),
            Self::Linear(pattern) => Ok(pattern
                .find(value)
                .is_some_and(|matched| matched.start() == 0)),
            Self::Backtracking(pattern) => pattern
                .find(value)
                .map(|matched| matched.is_some_and(|matched| matched.start() == 0))
                .map_err(|error| {
                    format!(
                        "Native regex evaluation failed within its backtracking budget: {error}"
                    )
                }),
        }
    }
}
