# Bellare-Micali 1-out-of-2 Oblivious Transfer

![Crates.io](https://img.shields.io/crates/v/bellare-micali.svg)
![Documentation](https://docs.rs/bellare-micali/badge.svg)
![Build Status](https://img.shields.io/github/actions/workflow/status/Cozy03/bellare-micali/ci.yml?branch=main)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
  - [Core Types](#core-types)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [Batch Processing Example](#batch-processing-example)
- [Protocol Steps](#protocol-steps)
- [Security Features](#security-features)
- [Testing](#testing)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [References](#references)

## Overview

The **Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) Protocol** is a foundational cryptographic primitive that enables secure communication between two parties:

- **Sender**: Possesses two messages.
- **Receiver**: Chooses one message to receive without revealing their choice to the sender.

Key properties of OT:

- **Receiver Privacy**: The sender remains oblivious to which message the receiver chose.
- **Sender Privacy**: The receiver gains no information about the unchosen message.

This Rust implementation leverages the **Ristretto group** (via the [curve25519-dalek](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/) crate) for elliptic curve operations, ensuring strong cryptographic security and efficient performance. The implementation is designed to be secure, type-safe, and easy to integrate into various applications requiring oblivious transfer.

## Features

- **Secure OT Protocol**: Implements the Bellare-Micali OT protocol with robust security measures.
- **Batch Processing**: Supports batch OT operations for improved efficiency using parallel processing.
- **Comprehensive Error Handling**: Custom error types facilitate precise and safe error management.
- **Cryptographic Utilities**: Provides essential cryptographic functions, including secure random scalar generation and hashing.
- **Modular Design**: Organized into distinct modules (`batch`, `crypto`, `error`, `protocol`, `types`) for clarity and maintainability.
- **Zeroization**: Sensitive data such as messages and cryptographic keys are automatically zeroized to prevent data leakage.
- **Documentation**: Well-documented code with Rustdoc comments and usage examples for ease of understanding and integration.

## Architecture

The project is structured into several modules, each responsible for specific aspects of the OT protocol:

- [`batch`](src/batch.rs): Handles batch processing of multiple OT transfers, optimizing performance through parallelism.
- [`crypto`](src/crypto.rs): Contains cryptographic utility functions and structures, such as random scalar generation and hashing.
- [`error`](src/error.rs): Defines the `OTError` enum, encapsulating all possible errors during protocol execution.
- [`protocol`](src/protocol.rs): Implements the core logic of the OT protocol, including sender and receiver operations.
- [`types`](src/types.rs): Defines fundamental types used across the crate, such as `Message`, `Ciphertext`, `Sender`, and `Receiver`.

### Core Types

#### Message

```rust
#[derive(Clone)]
pub struct Message(Vec<u8>);
```

Represents a message in the OT protocol. The `Message` struct ensures that its contents are securely managed and automatically zeroized when dropped to prevent sensitive data from lingering in memory.

#### Sender

```rust
pub struct Sender {
    u: Scalar,
    c: RistrettoPoint,
}
```

Maintains the sender's state during the protocol execution, including a private scalar `u` and a public point `c = G * u`, where `G` is the Ristretto basepoint.

#### Receiver

```rust
pub struct Receiver {
    k: Scalar,
    choice: bool,
}
```

Maintains the receiver's state and choice bit during protocol execution. The receiver's private scalar `k` determines which message they will receive.

#### Ciphertext

```rust
pub struct Ciphertext {
    v1: RistrettoPoint,
    v2: Vec<u8>,
}
```

Represents an encrypted message in the protocol, consisting of an elliptic curve point `v1` and an encrypted byte vector `v2`.

## Dependencies

The project relies on several crates for cryptographic operations, random number generation, error handling, and more.

```toml
[dependencies]
curve25519-dalek = { version = "4.1", features = ["rand_core"] }
rand = "0.8"
rand_core = "0.6"
sha2 = "0.10"
thiserror = "1.0"
zeroize = "1.8"
rayon = "1.7"
```

- **curve25519-dalek**: Provides the Ristretto group implementation for elliptic curve operations.
- **rand & rand_core**: Facilitate cryptographically secure random number generation.
- **sha2**: Used for hashing operations within the protocol.
- **thiserror**: Simplifies error type definitions.
- **zeroize**: Ensures that sensitive data is automatically cleared from memory when no longer needed.
- **rayon**: Enables parallel processing for batch OT operations.

## Installation

Add the crate to your project's `Cargo.toml`:

```toml
[dependencies]
bellare_micali = "0.1.0" # Replace with the actual version
```

Then, include it in your project:

```rust
use bellare_micali::{OTProtocol, Message, OTError};
```

## Usage

### Basic Example

Below is a simple example demonstrating how to initialize and execute the OT protocol.

```rust
use bellare_micali::{OTProtocol, Message};
use rand::rngs::OsRng;

fn main() -> Result<(), OTError> {
    let mut rng = OsRng;
    
    // Initialize sender
    let sender = OTProtocol::new_sender(&mut rng);
    
    // Create messages
    let msg0 = Message::new(b"First secret message".to_vec());
    let msg1 = Message::new(b"Second secret message".to_vec());
    
    // Initialize receiver with choice bit (true selects msg1)
    let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    
    // Generate receiver's public keys based on the choice bit
    let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    
    // Sender encrypts both messages
    let (c0, c1) = OTProtocol::sender_encrypt(
        &mut rng,
        &sender,
        pk0,
        pk1,
        &msg0,
        &msg1,
    )?;
    
    // Receiver decrypts the chosen ciphertext to obtain the message
    let decrypted = OTProtocol::receiver_decrypt(&receiver, &c0, &c1)?;
    
    println!("Decrypted message: {:?}", String::from_utf8(decrypted.as_bytes()).unwrap());
    
    Ok(())
}
```

### Batch Processing Example

For scenarios requiring multiple OT transfers simultaneously, utilize the batch processing capabilities.

```rust
use bellare_micali::{BatchOTProtocol, OTProtocol, Message};
use rand::rngs::OsRng;

fn main() -> Result<(), OTError> {
    let mut rng = OsRng;
    
    // Initialize sender
    let sender = OTProtocol::new_sender(&mut rng);
    
    // Create a batch of messages
    let msgs0 = vec![
        Message::new(b"Batch Secret0_1".to_vec()),
        Message::new(b"Batch Secret0_2".to_vec()),
    ];
    let msgs1 = vec![
        Message::new(b"Batch Secret1_1".to_vec()),
        Message::new(b"Batch Secret1_2".to_vec()),
    ];
    let choices = vec![false, true]; // Receiver choices
    
    // Perform batch OT transfers
    let decrypted_messages = BatchOTProtocol::batch_transfer(&mut rng, &msgs0, &msgs1, &choices)?;
    
    for (i, msg) in decrypted_messages.iter().enumerate() {
        println!("Decrypted message {}: {:?}", i + 1, String::from_utf8(msg.as_bytes()).unwrap());
    }
    
    Ok(())
}
```

## Protocol Steps

The OT protocol execution involves the following key steps:

### 1. Initialization

Initialize the sender and receiver. The sender generates a public key, and the receiver sets their choice bit.

```rust
// Sender initialization
let sender = OTProtocol::new_sender(&mut rng);

// Receiver initialization with choice bit
let receiver = OTProtocol::new_receiver(&mut rng, choice_bit, sender.c);
```

### 2. Key Generation

The receiver generates a pair of public keys based on their choice bit.

```rust
// Generate receiver's key pair
let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
```

### 3. Message Encryption

The sender encrypts both messages using the receiver's public keys.

```rust
let (c0, c1) = OTProtocol::sender_encrypt(
    &mut rng,
    &sender,
    pk0,
    pk1,
    &msg0,
    &msg1,
)?;
```

### 4. Message Decryption

The receiver decrypts the ciphertext corresponding to their choice bit to obtain the desired message.

```rust
let decrypted = OTProtocol::receiver_decrypt(&receiver, &c0, &c1)?;
```

## Security Features

1. **Zeroization**
   - **Automatic Clearing**: Sensitive data such as messages and cryptographic keys are automatically zeroized when dropped, preventing residual data from remaining in memory.
   
2. **Cryptographic Security**
   - **Ristretto Group**: Utilizes the Ristretto group for elliptic curve operations, ensuring strong security guarantees.
   - **Secure Randomness**: Employs cryptographically secure random number generators (`OsRng`) for scalar generation.
   - **Hashing**: Uses SHA-256 for hashing operations within the protocol.
   
3. **Error Handling**
   - **Custom Error Types**: Implements the `OTError` enum to represent protocol-specific errors, enabling precise and safe error management.
   - **Public Key Verification**: Validates that the sum of the receiver's public keys matches the sender's public point before encryption.
   
4. **Implementation Best Practices**
   - **Type Safety**: Ensures type-safe interfaces to prevent misuse.
   - **Memory Safety**: Avoids exposing sensitive data through careful memory management and zeroization.
   - **Constant-Time Operations**: Where possible, operations are implemented in a constant-time manner to mitigate timing attacks.

## Testing

The implementation includes comprehensive tests to verify the protocol's correctness and security.

### Running Tests

Execute all tests using Cargo:

```bash
cargo test
```

### Test Suite

- **Unit Tests**: Validate individual components and functions.
- **Integration Tests**: Ensure that different parts of the protocol work seamlessly together.
- **Property-Based Tests**: (If implemented) Verify that certain properties hold for a wide range of inputs.

### Example Test Cases

```rust
#[test]
fn test_complete_protocol_different_message_sizes() {
    // Test implementation
}

#[test_case(false ; "when choosing first message")]
#[test_case(true ; "when choosing second message")]
fn test_protocol_with_empty_messages(choice: bool) {
    // Test implementation
}

#[test]
fn test_invalid_public_keys() {
    // Test implementation
}
```

## Error Handling

The implementation uses a custom `OTError` enum to represent various errors that may occur during protocol execution.

```rust
pub enum OTError {
    InvalidPublicKey,
    ProtocolError(String),
}
```

### Error Variants

- **`InvalidPublicKey`**: Occurs when the receiver's public keys do not correctly sum to the sender's public point.
- **`ProtocolError`**: Represents generic protocol errors with descriptive messages.

### Propagating Errors

Functions return `Result` types to allow for safe and descriptive error handling.

```rust
fn some_protocol_function() -> Result<(), OTError> {
    // Function implementation
}
```

## Contributing

Contributions are welcome! To ensure a smooth collaboration process, please adhere to the following guidelines:

1. **Fork the Repository**: Create a personal copy of the project on GitHub.
2. **Create a Branch**: Use descriptive names for your branches, such as `feature/add-new-functionality` or `bugfix/fix-issue-123`.
3. **Write Tests**: Ensure that your contributions include relevant tests to verify functionality and prevent regressions.
4. **Follow Rust Best Practices**: Adhere to Rust's idiomatic practices, including proper formatting (`cargo fmt`) and linting (`cargo clippy`).
5. **Document Your Changes**: Update the README and provide Rustdoc comments for new modules or functions.
6. **Submit a Pull Request**: Describe your changes clearly, referencing any relevant issues or discussions.

## References

1. **Bellare, M., & Micali, S. (1989).** *Non-Interactive Oblivious Transfer and Applications*. [Link](https://link.springer.com/article/10.1007/BF00255296)
2. **curve25519-dalek Documentation**: [https://docs.rs/curve25519-dalek/latest/curve25519_dalek/](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/)
3. **Rust Cryptography Working Group Guidelines**: [https://github.com/RustCrypto](https://github.com/RustCrypto)
4. **Oblivious Transfer**: [Wikipedia](https://en.wikipedia.org/wiki/Oblivious_transfer)

---