//! # Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) Protocol Implementation
//!
//! This crate provides a secure and efficient implementation of the Bellare-Micali
//! 1-out-of-2 Oblivious Transfer (OT) protocol. The OT protocol is a fundamental
//! cryptographic primitive used in various secure multi-party computations and
//! protocols, including secure voting systems, private information retrieval, and
//! secure two-party computation.
//!
//! The implementation leverages the **Ristretto** group for elliptic curve operations,
//! ensuring strong security guarantees and efficient performance.
//!
//! ## Features
//!
//! - **Secure OT Protocol**: Implements the Bellare-Micali OT protocol with rigorous
//!   security measures.
//! - **Batch Processing**: Supports batch processing of OT operations for enhanced
//!   efficiency.
//! - **Comprehensive Error Handling**: Provides detailed error types to facilitate
//!   robust error handling.
//! - **Cryptographic Utilities**: Includes a suite of cryptographic utility functions
//!   essential for protocol operations.
//! - **Modular Design**: Organized into distinct modules for clarity, maintainability,
//!   and ease of extension.
//!
//! ## Modules
//!
//! - [`batch`](batch/index.html): Contains implementations for batch processing of OT
//!   operations, allowing multiple OT instances to be handled simultaneously for improved
//!   performance.
//! - [`crypto`](crypto/index.html): Houses cryptographic utility functions and structures
//!   used throughout the protocol, such as random scalar generation and hashing functions.
//! - [`error`](error/index.html): Defines the `OTError` enum, encapsulating all possible
//!   errors that can occur during the OT protocol execution.
//! - [`protocol`](protocol/index.html): Implements the core OT protocol logic, including
//!   the `OTProtocol` struct that manages the protocol's state and operations.
//! - [`types`](types/index.html): Defines fundamental types used across the crate, such
//!   as `Message` and `Ciphertext`, ensuring type safety and clarity.
//!
//! ## Re-Exports
//!
//! For convenience, the crate re-exports several commonly used items, allowing users to
//! access them directly from the crate root without needing to navigate through
//! individual modules.
//!
//! - [`OTError`](error::OTError): The primary error type for handling OT protocol errors.
//! - [`OTProtocol`](protocol::OTProtocol): The main struct managing the OT protocol's state
//!   and operations.
//! - [`Message`](types::Message): Represents messages transmitted within the OT protocol.
//! - [`BatchOTProtocol`](batch::BatchOTProtocol): Facilitates batch processing of multiple OT
//!   instances.
//!
//! ## Example
//!
//! Below is a simple example demonstrating how to initialize and execute the OT protocol.
//!
//! ```rust
//! use bellare_micali_ot::OTProtocol;
//! use curve25519_dalek::ristretto::RistrettoPoint;
//! use rand::rngs::OsRng;
//!
//! fn main() -> Result<(), bellare_micali_ot::OTError> {
//!     // Initialize the sender
//!     let mut rng = OsRng;
//!     let sender = OTProtocol::new_sender(&mut rng)?;
//!     
//!     // Initialize the receiver with a choice bit
//!     let receiver = OTProtocol::new_receiver(&mut rng, true)?;
//!     
//!     // Execute the protocol
//!     let ciphertext = sender.send(&receiver)?;
//!     let message = receiver.receive(&ciphertext)?;
//!     
//!     println!("Received message: {:?}", message.as_bytes());
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - **Randomness**: The protocol relies on cryptographically secure random number generators.
//!   Ensure that a secure RNG is used to prevent potential vulnerabilities.
//! - **Key Management**: Properly manage and protect all cryptographic keys and scalars to
//!   maintain protocol security.
//! - **Dependencies**: Keep all dependencies up-to-date to benefit from the latest security
//!   patches and improvements.
//!
//! ## License
//!
//! This project is licensed under the [MIT License](LICENSE).

pub mod batch;
pub mod crypto;
pub mod error;
pub mod protocol;
pub mod types;

// Re-export commonly used items for easier access
pub use crate::batch::BatchOTProtocol;
pub use crate::error::OTError;
pub use crate::protocol::OTProtocol;
pub use crate::types::Message;
