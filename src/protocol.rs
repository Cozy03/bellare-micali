use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::RistrettoPoint;
use rand_core::{CryptoRng, RngCore};

use crate::crypto::CryptoUtils;
use crate::error::OTError;
use crate::types::{Ciphertext, Message, Receiver, Sender};

/// Implementation of the Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) Protocol.
///
/// The `OTProtocol` struct provides the core functionalities required to execute the
/// Bellare-Micali OT protocol. This protocol allows a sender to transfer one of two
/// messages to a receiver based on the receiver's choice, without the sender learning
/// which message was chosen.
///
/// The implementation leverages the Ristretto group for elliptic curve operations,
/// ensuring strong security guarantees and efficient performance.
pub struct OTProtocol;

impl OTProtocol {
    /// Initializes a new sender for the OT protocol.
    ///
    /// This function generates a random scalar `u` and computes the corresponding public
    /// Ristretto point `c` using the Ristretto basepoint `G`. The sender's state is then
    /// encapsulated within the `Sender` struct.
    ///
    /// # Type Parameters
    ///
    /// - `R`: A type that implements both `RngCore` and `CryptoRng`, ensuring cryptographic
    ///        security of the random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator that implements `RngCore`
    ///           and `CryptoRng`.
    ///
    /// # Returns
    ///
    /// * `Sender` - The initialized sender with a private scalar `u` and public point `c`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::OTProtocol;
    ///
    /// let mut rng = OsRng;
    /// let sender = OTProtocol::new_sender(&mut rng);
    /// ```
    pub fn new_sender<R: RngCore + CryptoRng>(rng: &mut R) -> Sender {
        let u = CryptoUtils::random_scalar(rng);
        let c = G * u;
        Sender { u, c }
    }

    /// Initializes a new receiver with a specified choice bit for the OT protocol.
    ///
    /// This function generates a random scalar `k` and sets the receiver's choice bit,
    /// determining which of the two messages the receiver will obtain. The receiver's
    /// state is encapsulated within the `Receiver` struct.
    ///
    /// # Type Parameters
    ///
    /// - `R`: A type that implements both `RngCore` and `CryptoRng`, ensuring cryptographic
    ///        security of the random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator that implements `RngCore`
    ///           and `CryptoRng`.
    /// * `choice` - A boolean indicating the receiver's selection in the OT protocol.
    ///              If `true`, the receiver chooses the second message; otherwise, the first.
    /// * `_c` - A `RistrettoPoint` provided by the sender. (Note: The parameter name starts
    ///          with an underscore, indicating that it is currently unused.)
    ///
    /// # Returns
    ///
    /// * `Receiver` - The initialized receiver with a private scalar `k` and choice bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::{OTProtocol, Receiver};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// let mut rng = OsRng;
    /// let c = RistrettoPoint::default(); // Placeholder for actual `c` from sender
    /// let receiver = OTProtocol::new_receiver(&mut rng, true, c);
    /// ```
    pub fn new_receiver<R: RngCore + CryptoRng>(
        rng: &mut R,
        choice: bool,
        _c: RistrettoPoint,
    ) -> Receiver {
        let k = CryptoUtils::random_scalar(rng);
        Receiver { k, choice }
    }

    /// Generates the receiver's public keys based on the choice bit.
    ///
    /// This function computes two public keys, `pk_b` and `pk_not_b`, using the receiver's
    /// private scalar `k` and the sender's public point `c`. Depending on the receiver's
    /// choice bit, the function returns the appropriate pair of public keys to ensure
    /// that only the chosen message can be decrypted by the receiver.
    ///
    /// # Arguments
    ///
    /// * `receiver` - A reference to the `Receiver` struct containing the receiver's state.
    /// * `c` - The sender's public Ristretto point.
    ///
    /// # Returns
    ///
    /// * `(RistrettoPoint, RistrettoPoint)` - A tuple containing the two public keys.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::{OTProtocol, Sender, Receiver};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// let mut rng = OsRng;
    /// let sender = OTProtocol::new_sender(&mut rng);
    /// let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    /// let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    /// ```
    pub fn receiver_generate_keys(
        receiver: &Receiver,
        c: RistrettoPoint,
    ) -> (RistrettoPoint, RistrettoPoint) {
        let pk_b = G * receiver.k;
        let pk_not_b = c - pk_b;

        if receiver.choice {
            (pk_not_b, pk_b)
        } else {
            (pk_b, pk_not_b)
        }
    }

    /// Verifies the receiver's public keys and encrypts the sender's messages.
    ///
    /// This function performs the following steps:
    /// 1. Verifies that the sum of the receiver's public keys `pk0` and `pk1` equals the
    ///    sender's public point `c`.
    /// 2. Generates random scalars `r0` and `r1` for encrypting the messages.
    /// 3. Encrypts each message using the corresponding public key and random scalar.
    ///
    /// # Type Parameters
    ///
    /// - `R`: A type that implements both `RngCore` and `CryptoRng`, ensuring cryptographic
    ///        security of the random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator that implements `RngCore`
    ///           and `CryptoRng`.
    /// * `sender` - A reference to the `Sender` struct containing the sender's state.
    /// * `pk0` - The first public key generated by the receiver.
    /// * `pk1` - The second public key generated by the receiver.
    /// * `msg0` - A reference to the first `Message` to be sent.
    /// * `msg1` - A reference to the second `Message` to be sent.
    ///
    /// # Returns
    ///
    /// * `Result<(Ciphertext, Ciphertext), OTError>` - On success, returns a tuple containing
    ///   two `Ciphertext` instances corresponding to the encrypted messages. On failure,
    ///   returns an `OTError`.
    ///
    /// # Errors
    ///
    /// * `OTError::InvalidPublicKey` - If the sum of `pk0` and `pk1` does not equal the sender's
    ///   public point `c`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::{OTProtocol, Sender, Receiver, Message, Ciphertext, OTError};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// let mut rng = OsRng;
    /// let sender = OTProtocol::new_sender(&mut rng);
    /// let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    /// let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    /// let msg0 = Message::new(b"Secret 0".to_vec());
    /// let msg1 = Message::new(b"Secret 1".to_vec());
    ///
    /// let ciphertexts = OTProtocol::sender_encrypt(
    ///     &mut rng,
    ///     &sender,
    ///     pk0,
    ///     pk1,
    ///     &msg0,
    ///     &msg1,
    /// ).expect("Encryption failed");
    /// ```
    pub fn sender_encrypt<R: RngCore + CryptoRng>(
        rng: &mut R,
        sender: &Sender,
        pk0: RistrettoPoint,
        pk1: RistrettoPoint,
        msg0: &Message,
        msg1: &Message,
    ) -> Result<(Ciphertext, Ciphertext), OTError> {
        // Verify public keys
        if pk0 + pk1 != sender.c {
            return Err(OTError::InvalidPublicKey);
        }

        // Generate random values for encryption
        let r0 = CryptoUtils::random_scalar(rng);
        let r1 = CryptoUtils::random_scalar(rng);

        // Encrypt first message
        let gr0 = G * r0;
        let pk0r0 = pk0 * r0;
        let c0 = Self::encrypt_message(&pk0r0, msg0);

        // Encrypt second message
        let gr1 = G * r1;
        let pk1r1 = pk1 * r1;
        let c1 = Self::encrypt_message(&pk1r1, msg1);

        Ok((
            Ciphertext { v1: gr0, v2: c0 },
            Ciphertext { v1: gr1, v2: c1 },
        ))
    }

    /// Decrypts the chosen ciphertext based on the receiver's choice bit.
    ///
    /// This function performs the following steps:
    /// 1. Selects the ciphertext corresponding to the receiver's choice.
    /// 2. Computes the shared key by multiplying the ciphertext's `v1` with the receiver's
    ///    private scalar `k`.
    /// 3. Decrypts the ciphertext using the shared key to retrieve the original message.
    ///
    /// # Arguments
    ///
    /// * `receiver` - A reference to the `Receiver` struct containing the receiver's state.
    /// * `c0` - A reference to the first `Ciphertext` received from the sender.
    /// * `c1` - A reference to the second `Ciphertext` received from the sender.
    ///
    /// # Returns
    ///
    /// * `Result<Message, OTError>` - On success, returns the decrypted `Message` corresponding
    ///   to the receiver's choice. On failure, returns an `OTError`.
    ///
    /// # Errors
    ///
    /// * `OTError::ProtocolError` - If decryption fails due to invalid ciphertext or other
    ///   protocol inconsistencies.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::{OTProtocol, Sender, Receiver, Message, Ciphertext, OTError};
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// let mut rng = OsRng;
    /// let sender = OTProtocol::new_sender(&mut rng);
    /// let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    /// let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    /// let msg0 = Message::new(b"Secret 0".to_vec());
    /// let msg1 = Message::new(b"Secret 1".to_vec());
    ///
    /// let (c0, c1) = OTProtocol::sender_encrypt(
    ///     &mut rng,
    ///     &sender,
    ///     pk0,
    ///     pk1,
    ///     &msg0,
    ///     &msg1,
    /// ).expect("Encryption failed");
    ///
    /// let decrypted = OTProtocol::receiver_decrypt(&receiver, &c0, &c1).expect("Decryption failed");
    /// assert_eq!(decrypted.as_bytes(), msg1.as_bytes());
    /// ```
    pub fn receiver_decrypt(
        receiver: &Receiver,
        c0: &Ciphertext,
        c1: &Ciphertext,
    ) -> Result<Message, OTError> {
        let cb = if receiver.choice { c1 } else { c0 };

        // Compute shared key
        let shared_key = cb.v1 * receiver.k;

        // Decrypt message
        let msg = Self::decrypt_message(&shared_key, &cb.v2)?;
        Ok(Message::new(msg))
    }

    /// Encrypts a message using the provided key point.
    ///
    /// This private helper function performs the encryption by hashing the key point to
    /// derive a symmetric key of the same length as the message and then applying a
    /// bitwise XOR operation between the key and the message bytes.
    ///
    /// # Arguments
    ///
    /// * `key_point` - A reference to the `RistrettoPoint` used to derive the encryption key.
    /// * `msg` - A reference to the `Message` to be encrypted.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector containing the encrypted message bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    /// use bellare_micali_ot::{OTProtocol, Message};
    ///
    /// let key_point = RistrettoPoint::default();
    /// let msg = Message::new(b"Secret".to_vec());
    /// let encrypted = OTProtocol::encrypt_message(&key_point, &msg);
    /// ```
    fn encrypt_message(key_point: &RistrettoPoint, msg: &Message) -> Vec<u8> {
        let msg_bytes = msg.as_bytes();
        let key = CryptoUtils::hash_point_to_length(key_point, msg_bytes.len());
        CryptoUtils::xor_bytes(&key, msg_bytes)
    }

    /// Decrypts a ciphertext using the provided key point.
    ///
    /// This private helper function performs the decryption by hashing the key point to
    /// derive a symmetric key of the same length as the ciphertext and then applying a
    /// bitwise XOR operation between the key and the ciphertext bytes.
    ///
    /// # Arguments
    ///
    /// * `key_point` - A reference to the `RistrettoPoint` used to derive the decryption key.
    /// * `ciphertext` - A byte slice containing the encrypted message.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, OTError>` - On success, returns a vector containing the decrypted
    ///   message bytes. On failure, returns an `OTError`.
    ///
    /// # Errors
    ///
    /// * `OTError::ProtocolError` - If decryption fails due to invalid ciphertext or other
    ///   protocol inconsistencies.
    ///
    /// # Example
    ///
    /// ```rust
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    /// use bellare_micali_ot::{OTProtocol, OTError};
    ///
    /// let key_point = RistrettoPoint::default();
    /// let ciphertext = vec![0u8; 10]; // Placeholder for actual ciphertext
    /// let decrypted = OTProtocol::decrypt_message(&key_point, &ciphertext)
    ///     .expect("Decryption failed");
    /// ```
    fn decrypt_message(key_point: &RistrettoPoint, ciphertext: &[u8]) -> Result<Vec<u8>, OTError> {
        let key = CryptoUtils::hash_point_to_length(key_point, ciphertext.len());
        Ok(CryptoUtils::xor_bytes(&key, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Tests the basic functionality of the OT protocol for both choice bits.
    ///
    /// This test performs the following steps:
    /// 1. Initializes a sender and two messages.
    /// 2. For each choice bit (`false` and `true`):
    ///    - Initializes a receiver with the current choice bit.
    ///    - Generates the receiver's public keys.
    ///    - Encrypts the messages using the sender's encrypt function.
    ///    - Decrypts the chosen ciphertext using the receiver's decrypt function.
    ///    - Asserts that the decrypted message matches the expected message based on the choice bit.
    #[test]
    fn test_basic_protocol() {
        let mut rng = OsRng;
        let sender = OTProtocol::new_sender(&mut rng);
        let msg0 = Message::new(b"Secret 0".to_vec());
        let msg1 = Message::new(b"Secret 1".to_vec());

        // Test both choice bits
        for &choice in &[false, true] {
            let receiver = OTProtocol::new_receiver(&mut rng, choice, sender.c);
            let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);

            let (c0, c1) = OTProtocol::sender_encrypt(&mut rng, &sender, pk0, pk1, &msg0, &msg1)
                .expect("Encryption failed");

            let decrypted =
                OTProtocol::receiver_decrypt(&receiver, &c0, &c1).expect("Decryption failed");

            if choice {
                assert_eq!(decrypted.as_bytes(), msg1.as_bytes());
            } else {
                assert_eq!(decrypted.as_bytes(), msg0.as_bytes());
            }
        }
    }
}
