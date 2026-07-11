use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertaelError {
    #[error("session is not active")]
    SessionInactive,
    #[error("session has expired")]
    SessionExpired,
    #[error("payload exceeds configured limit")]
    PayloadTooLarge,
    #[error("action type is invalid")]
    InvalidActionType,
    #[error("sequence number exhausted")]
    SequenceExhausted,
    #[error("serialization failed")]
    Serialization,
    #[error("cryptographic operation failed")]
    Cryptography,
    #[error("invalid argument")]
    InvalidArgument,
}

pub type Result<T> = core::result::Result<T, CertaelError>;
