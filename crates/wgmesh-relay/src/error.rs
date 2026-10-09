use std::fmt;

#[derive(Debug)]
pub enum RelayError {
    Socket(Box<dyn std::error::Error + Send + Sync + 'static>),
    UnknownPort(u16),
    Config(String),
}

impl RelayError {
    pub fn socket<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Socket(Box::new(error))
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(error) => write!(f, "slot socket: {error}"),
            Self::UnknownPort(port) => write!(f, "no slot socket bound on port {port}"),
            Self::Config(detail) => write!(f, "configuration: {detail}"),
        }
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
