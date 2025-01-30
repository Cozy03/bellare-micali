use curve25519_dalek::{RistrettoPoint, Scalar};
use zeroize::Zeroize;

/// Represents a message in the Oblivious Transfer (OT) protocol.
///
/// The `Message` struct encapsulates a byte vector that holds the actual message data.
/// It ensures that the message data is securely erased from memory when the `Message` instance is dropped.
#[derive(Clone)]
pub struct Message(Vec<u8>);

impl Message {
    /// Creates a new `Message` instance with the provided data.
    ///
    /// # Arguments
    ///
    /// * `data` - A `Vec<u8>` containing the message data.
    ///
    /// # Example
    ///
    /// ```
    /// let msg = Message::new(vec![1, 2, 3]);
    /// ```
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Returns a byte slice of the message data.
    ///
    /// # Returns
    ///
    /// A reference to the byte slice containing the message data.
    ///
    /// # Example
    ///
    /// ```
    /// let msg = Message::new(vec![1, 2, 3]);
    /// assert_eq!(msg.as_bytes(), &[1, 2, 3]);
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Message {
    /// Overrides the default `drop` behavior to securely erase the message data from memory.
    ///
    /// Utilizes the `zeroize` crate to overwrite the data with zeros, preventing potential
    /// sensitive information leakage.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Represents the sender's state in the Oblivious Transfer (OT) protocol.
///
/// The `Sender` struct maintains the sender's private scalar `u` and the public Ristretto point `c`.
pub struct Sender {
    /// The sender's private scalar value.
    ///
    /// This scalar is used in cryptographic computations to generate the public point `c`.
    #[allow(dead_code)]
    pub(crate) u: Scalar, // Changed from private to pub(crate)

    /// The sender's public Ristretto point.
    ///
    /// This point is derived from the private scalar `u` and is shared with the receiver.
    pub c: RistrettoPoint,
}

impl Sender {
    /// Initializes a new `Sender` with a randomly generated scalar and corresponding Ristretto point.
    ///
    /// # Example
    ///
    /// ```
    /// let sender = Sender::new();
    /// ```
    pub fn new() -> Self {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use rand::rngs::OsRng;

        let u = Scalar::random(&mut OsRng);
        let c = &u * &RISTRETTO_BASEPOINT_POINT;
        Sender { u, c }
    }

    // Additional methods for the Sender can be implemented here.
}

/// Represents the receiver's state in the Oblivious Transfer (OT) protocol.
///
/// The `Receiver` struct maintains the receiver's private scalar `k` and a boolean `choice`
pub struct Receiver {
    /// The receiver's private scalar value.
    ///
    /// This scalar is used in cryptographic computations based on the receiver's choice.
    pub(crate) k: Scalar,

    /// The receiver's choice in the OT protocol.
    ///
    /// Determines which message the receiver will obtain from the sender.
    pub(crate) choice: bool,
}

impl Receiver {
    /// Initializes a new `Receiver` with a randomly generated scalar and a choice.
    ///
    /// # Arguments
    ///
    /// * `choice` - A boolean indicating the receiver's selection in the OT protocol.
    ///
    /// # Example
    ///
    /// ```
    /// let receiver = Receiver::new(true);
    /// ```
    pub fn new(choice: bool) -> Self {
        use rand::rngs::OsRng;

        let k = Scalar::random(&mut OsRng);
        Receiver { k, choice }
    }

    // Additional methods for the Receiver can be implemented here.
}

/// Represents the ciphertext structure for encrypted messages in the OT protocol.
///
/// The `Ciphertext` struct contains two components:
/// - `v1`: A Ristretto point representing part of the encrypted message.
/// - `v2`: A byte vector containing the encrypted data.
#[derive(Clone)]
pub struct Ciphertext {
    /// The first component of the ciphertext, a Ristretto point.
    pub v1: RistrettoPoint,

    /// The second component of the ciphertext, containing encrypted bytes.
    pub v2: Vec<u8>,
}

impl Zeroize for Ciphertext {
    /// Securely erases the ciphertext data from memory by zeroizing the `v2` field.
    ///
    /// This ensures that sensitive encrypted data does not remain in memory after the ciphertext is dropped.
    fn zeroize(&mut self) {
        self.v2.zeroize();
    }
}

impl Ciphertext {
    /// Creates a new `Ciphertext` instance with the provided Ristretto point and data.
    ///
    /// # Arguments
    ///
    /// * `v1` - A `RistrettoPoint` representing the first part of the ciphertext.
    /// * `v2` - A `Vec<u8>` containing the encrypted message data.
    ///
    /// # Example
    ///
    /// ```
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    /// let point = RistrettoPoint::default();
    /// let data = vec![1, 2, 3];
    /// let ciphertext = Ciphertext::new(point, data);
    /// ```
    pub fn new(v1: RistrettoPoint, v2: Vec<u8>) -> Self {
        Ciphertext { v1, v2 }
    }

    /// Retrieves a reference to the first component of the ciphertext (`v1`).
    ///
    /// # Returns
    ///
    /// A reference to the `RistrettoPoint` representing `v1`.
    pub fn v1(&self) -> &RistrettoPoint {
        &self.v1
    }

    /// Retrieves a reference to the second component of the ciphertext (`v2`).
    ///
    /// # Returns
    ///
    /// A reference to the byte vector containing `v2`.
    pub fn v2(&self) -> &[u8] {
        &self.v2
    }
}

// Additional module-level documentation can be added here if necessary.
