use thiserror::Error;

/// Errors that can occur during the Oblivious Transfer (OT) protocol.
///
/// The `OTError` enum encapsulates various error types that may arise
/// during the execution of the OT protocol. It leverages the `thiserror`
/// crate to provide descriptive and user-friendly error messages.
///
/// # Variants
///
/// - [`InvalidPublicKey`](OTError::InvalidPublicKey):
///     Indicates a failure in verifying a public key.
/// - [`ProtocolError`](OTError::ProtocolError):
///     Represents a generic protocol-related error with a descriptive message.
#[derive(Error, Debug)]
pub enum OTError {
    /// Indicates a failure in verifying a public key.
    ///
    /// This error is returned when the provided public key does not pass
    /// the necessary validation checks, such as being on the correct elliptic
    /// curve or meeting specific protocol requirements.
    ///
    /// # Example
    ///
    /// ```rust
    /// return Err(OTError::InvalidPublicKey);
    /// ```
    #[error("Invalid public key verification")]
    InvalidPublicKey,

    /// Represents a generic protocol-related error with a descriptive message.
    ///
    /// This variant is used to capture and convey various protocol-specific
    /// errors that do not fall under more specific categories. The accompanying
    /// `String` provides additional context or details about the error.
    ///
    /// # Arguments
    ///
    /// * `message` - A `String` detailing the nature of the protocol error.
    ///
    /// # Example
    ///
    /// ```rust
    /// return Err(OTError::ProtocolError("Unexpected message format".into()));
    /// ```
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

impl OTError {
    /// Creates a new `InvalidPublicKey` error.
    ///
    /// # Example
    ///
    /// ```rust
    /// let error = OTError::new_invalid_public_key();
    /// ```
    pub fn new_invalid_public_key() -> Self {
        OTError::InvalidPublicKey
    }

    /// Creates a new `ProtocolError` with a descriptive message.
    ///
    /// # Arguments
    ///
    /// * `message` - A `String` describing the protocol error.
    ///
    /// # Example
    ///
    /// ```rust
    /// let error = OTError::new_protocol_error("Missing required field".into());
    /// ```
    pub fn new_protocol_error(message: String) -> Self {
        OTError::ProtocolError(message)
    }
}
