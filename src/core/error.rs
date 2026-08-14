use thiserror::Error;

pub type Result<T> = std::result::Result<T, SherlockError>;

#[derive(Debug, Error)]
pub enum SherlockError {
    #[error("invalid identifier: {0}")]
    InvalidId(String),

    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("scope violation: {0}")]
    Scope(String),

    #[error("scan policy denied: {0}")]
    Policy(String),

    #[error("authorization required: {0}")]
    Authorization(String),

    #[error("case not found: {0}")]
    CaseNotFound(String),

    #[error("finding not found: {0}")]
    FindingNotFound(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("engine error ({engine}): {message}")]
    Engine { engine: String, message: String },

    #[error("report error: {0}")]
    Report(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http error: {0}")]
    Http(String),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

impl From<rusqlite::Error> for SherlockError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<reqwest::Error> for SherlockError {
    fn from(value: reqwest::Error) -> Self {
        Self::Network(value.to_string())
    }
}

impl From<anyhow::Error> for SherlockError {
    fn from(value: anyhow::Error) -> Self {
        Self::Other(value.to_string())
    }
}
