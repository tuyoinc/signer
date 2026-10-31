use std::fmt;

/// An error with a stable machine-readable code, safe to show to agents.
/// Messages never contain key material, signatures or file contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerError {
    pub code: &'static str,
    pub message: String,
}

impl SignerError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SignerError {}

pub type Result<T> = std::result::Result<T, SignerError>;
