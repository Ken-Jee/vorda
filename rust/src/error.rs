use std::fmt;

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub class: String,
    pub http_status: Option<u16>,
    /// A sqlite busy/locked code: the store is held by another transaction and a retry may succeed.
    pub busy: bool,
    /// The command line was malformed (exit 64); `link` then prints the message, not the class.
    pub usage: bool,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            usage: true,
            ..Self::new(message)
        }
    }

    pub fn is_usage(&self) -> bool {
        self.usage
    }

    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: "ValueError".into(),
            http_status: None,
            usage: false,
            busy: false,
        }
    }

    /// A fixed instruction for the operator. `link` errors print only their class, so the text is the class too;
    /// it must never hold result data or paths.
    pub fn instruction(message: &str) -> Self {
        Self {
            message: message.into(),
            class: message.into(),
            http_status: None,
            usage: false,
            busy: false,
        }
    }

    pub fn rejected(status: u16, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: "Rejected".into(),
            http_status: Some(status),
            usage: false,
            busy: false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self {
            message: error.to_string(),
            class: "OSError".into(),
            http_status: None,
            usage: false,
            busy: false,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self {
            message: error.to_string(),
            class: "ValueError".into(),
            http_status: None,
            usage: false,
            busy: false,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self {
            message: error.to_string(),
            class: "Error".into(),
            http_status: None,
            usage: false,
            busy: matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            ),
        }
    }
}
