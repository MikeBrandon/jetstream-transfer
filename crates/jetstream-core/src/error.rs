use std::io;

use crate::identity::DeviceId;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("could not locate a per-user data directory for this platform")]
    NoDataDir,

    #[error("identity key at {path} is malformed: {detail}")]
    MalformedIdentity { path: String, detail: String },

    #[error("could not unwrap the identity key (was it copied from another machine or user account?)")]
    IdentityUnwrap,

    #[error("cryptography error: {0}")]
    Crypto(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    /// The peer completed a TLS handshake but presented a different device
    /// identity than the one we pinned. This is the signature of either a
    /// machine that reinstalled, or an active man-in-the-middle.
    #[error("device identity mismatch: expected {expected}, peer presented {actual}")]
    IdentityMismatch {
        expected: Box<DeviceId>,
        actual: Box<DeviceId>,
    },

    #[error("transport error: {0}")]
    Transport(String),

    #[error("connection closed by peer: {0}")]
    ConnectionClosed(String),

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("message of {size} bytes exceeds the {limit} byte limit for this frame")]
    FrameTooLarge { size: usize, limit: usize },

    #[error("peer rejected the transfer: {0}")]
    Rejected(String),

    /// Stopped by the user, and not to be continued.
    ///
    /// Separate from [`Error::Rejected`], which it used to share. A local cancel
    /// surfaced as a rejection, so the UI reported the user's own click as
    /// "declined" — a word that means *the other person said no*.
    #[error("cancelled")]
    Cancelled,

    /// Stopped by the user, to be continued later.
    ///
    /// Distinct from [`Error::Cancelled`] because everything downstream treats
    /// them oppositely: a pause keeps its place in the list and waits, a cancel
    /// is done with. Crucially a pause must not look like a dropped connection,
    /// or the automatic retry would restart what the user just stopped.
    #[error("paused")]
    Paused,

    #[error("unsupported protocol version: peer speaks {peer}, we speak {ours}")]
    VersionMismatch { peer: u16, ours: u16 },
}

/// quinn's stream types expose inherent `write_all`/`read_exact` with their own
/// error types, so `?` needs these to reach [`Error`].
impl From<quinn::WriteError> for Error {
    fn from(e: quinn::WriteError) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<quinn::ReadError> for Error {
    fn from(e: quinn::ReadError) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<quinn::ReadExactError> for Error {
    fn from(e: quinn::ReadExactError) -> Self {
        Self::Transport(e.to_string())
    }
}

impl From<quinn::ClosedStream> for Error {
    fn from(e: quinn::ClosedStream) -> Self {
        Self::Transport(e.to_string())
    }
}

impl Error {
    pub(crate) fn crypto(e: impl std::fmt::Display) -> Self {
        Self::Crypto(e.to_string())
    }

    pub(crate) fn cert(e: impl std::fmt::Display) -> Self {
        Self::Certificate(e.to_string())
    }

    pub(crate) fn transport(e: impl std::fmt::Display) -> Self {
        Self::Transport(e.to_string())
    }
}
