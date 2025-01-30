# **Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) Protocol** 🚀  

![Crates.io](https://img.shields.io/crates/v/bellare-micali.svg)
![Documentation](https://docs.rs/bellare-micali/badge.svg)
![Build Status](https://img.shields.io/github/actions/workflow/status/Cozy03/bellare-micali/ci.yml?branch=main)

**Bellare-Micali 1-out-of-2 Oblivious Transfer (OT)** is a cryptographic protocol that enables a sender to send one of two messages to a receiver, who selects a message without revealing their choice. This ensures privacy and security in multi-party computations, secure voting, and private information retrieval.

---

## **📌 Table of Contents**
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
  - [Core Components](#core-components)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [Batch Processing](#batch-processing)
- [Security Considerations](#security-considerations)
- [Testing & Error Handling](#testing--error-handling)
- [About My Notes](#about-my-notes)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

---

## **🔍 Overview**
The **Bellare-Micali Oblivious Transfer Protocol** allows:
- A **sender** to securely send two messages.
- A **receiver** to choose one message while keeping their choice private.
- Neither party gains additional information beyond their expected outputs.

This implementation uses **Ristretto group operations** for strong security and efficient computation, making it ideal for privacy-preserving cryptographic protocols.

---

## **✨ Features**
✔️ **Secure OT Protocol** – Strong privacy guarantees for sender and receiver.  
⚡ **Batch Processing** – Perform multiple OT transfers in parallel.  
🛡️ **Cryptographic Utilities** – Secure random scalars, hashing, and more.  
📜 **Comprehensive Documentation** – Includes Rustdoc and usage examples.  
🛠 **Error Handling** – Custom `OTError` for clear debugging.  
🔑 **Zeroization** – Ensures cryptographic secrets are wiped from memory.  

---

## **🛠 Architecture**
This implementation follows a modular approach:

- 🏗 [`batch`](src/batch.rs) – Handles parallel OT executions for efficiency.
- 🔐 [`crypto`](src/crypto.rs) – Provides cryptographic tools like hashing.
- ⚠️ [`error`](src/error.rs) – Defines `OTError` for exception handling.
- 🔄 [`protocol`](src/protocol.rs) – Implements sender/receiver OT operations.
- 🗂 [`types`](src/types.rs) – Defines fundamental types like `Message`, `Sender`, and `Receiver`.

### **Core Components**
#### **Message**
```rust
pub struct Message(Vec<u8>);
```
Stores and manages OT messages securely.

#### **Sender**
```rust
pub struct Sender {
    u: Scalar,
    c: RistrettoPoint,
}
```
Represents the sender’s cryptographic state.

#### **Receiver**
```rust
pub struct Receiver {
    k: Scalar,
    choice: bool,
}
```
Handles the receiver’s private key and message choice.

#### **Ciphertext**
```rust
pub struct Ciphertext {
    v1: RistrettoPoint,
    v2: Vec<u8>,
}
```
Stores encrypted messages securely.

---

## **📥 Installation**
Add this crate to your Rust project:

```toml
[dependencies]
bellare_micali = "0.1.1"
```

Include it in your Rust code:
```rust
use bellare_micali::{OTProtocol, Message, OTError};
```

---

## **💡 Usage**
### **Basic Example**
```rust
use bellare_micali::{OTProtocol, Message};
use rand::rngs::OsRng;

fn main() -> Result<(), OTError> {
    let mut rng = OsRng;
    let sender = OTProtocol::new_sender(&mut rng);
    let msg0 = Message::new(b"Secret 1".to_vec());
    let msg1 = Message::new(b"Secret 2".to_vec());
    let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    let (c0, c1) = OTProtocol::sender_encrypt(&mut rng, &sender, pk0, pk1, &msg0, &msg1)?;
    let decrypted = OTProtocol::receiver_decrypt(&receiver, &c0, &c1)?;
    println!("Decrypted: {:?}", String::from_utf8(decrypted.as_bytes()).unwrap());
    Ok(())
}
```

### **Batch Processing**
For handling multiple messages efficiently:
```rust
use bellare_micali::{BatchOTProtocol, OTProtocol, Message};
use rand::rngs::OsRng;

fn main() -> Result<(), OTError> {
    let mut rng = OsRng;
    let sender = OTProtocol::new_sender(&mut rng);
    let msgs0 = vec![Message::new(b"Batch 1".to_vec()), Message::new(b"Batch 2".to_vec())];
    let msgs1 = vec![Message::new(b"Batch A".to_vec()), Message::new(b"Batch B".to_vec())];
    let choices = vec![false, true];

    let decrypted_messages = BatchOTProtocol::batch_transfer(&mut rng, &msgs0, &msgs1, &choices)?;
    
    for (i, msg) in decrypted_messages.iter().enumerate() {
        println!("Decrypted Message {}: {:?}", i + 1, String::from_utf8(msg.as_bytes()).unwrap());
    }

    Ok(())
}
```

---

## **🛡 Security Considerations**
✅ **Zeroization of sensitive data** using `zeroize`.  
✅ **Elliptic curve security** via the Ristretto group.  
✅ **Secure randomness** using `rand::rngs::OsRng`.  
✅ **Strict error handling** to prevent protocol misuse.  

---

## **🧪 Testing & Error Handling**
Run tests:
```sh
cargo test
```
The `OTError` enum provides clear error handling:
```rust
pub enum OTError {
    InvalidPublicKey,
    ProtocolError(String),
}
```

---

## **📖 About My Notes**
I have included additional notes and theoretical explanations regarding **Oblivious Transfer and Multi-Party Computation (MPC)** in the document **`Bellare_Micali_Oblivious_Transfer.pdf`**.  

These notes provide:
- 📌 An overview of the **Bellare-Micali OT Protocol**.
- 📖 Explanation of **Elliptic Curve Cryptography** in the protocol.
- 🔢 **Mathematical formulation** of sender and receiver interactions.
- 🛠 **Practical use cases** in secure communication.

---

## **🤝 Contributing**
Contributions are welcome! To contribute:
1. **Fork the repository**.
2. **Create a feature branch** (`feature/your-feature-name`).
3. **Write tests** and ensure existing tests pass.
4. **Submit a pull request**.

---

## **📜 License**
This project is licensed under the **MIT License**.

```txt
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction...
```
_(Full license text available in the `LICENSE` file.)_

---

## **📚 References**
1. **Bellare & Micali (1989)** – *Non-Interactive Oblivious Transfer* [Link](https://cseweb.ucsd.edu/~mihir/papers/niot.pdf).
2. **curve25519-dalek Docs** – [Docs.rs](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/).
3. **Oblivious Transfer (Wikipedia)** – [Wiki](https://en.wikipedia.org/wiki/Oblivious_transfer).

---