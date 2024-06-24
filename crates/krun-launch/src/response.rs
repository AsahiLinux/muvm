use std::fmt;

#[derive(Clone, Debug)]
pub enum Response {
    Ok,
    Err { msg: String },
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Err { msg } => write!(f, "{msg}"),
        }
    }
}
