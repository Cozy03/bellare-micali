use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// Cryptographic utility functions for the Oblivious Transfer (OT) protocol.
///
/// The `CryptoUtils` struct provides a collection of static methods that facilitate
/// various cryptographic operations essential for the OT protocol. These utilities
/// include generating random scalars, hashing Ristretto points to arbitrary lengths,
/// and performing XOR operations on byte slices.
pub(crate) struct CryptoUtils;

impl CryptoUtils {
    /// Generates a random scalar using a cryptographically secure random number generator.
    ///
    /// This function leverages the provided random number generator (`rng`) to produce
    /// a random scalar within the field defined by Curve25519. It ensures that the
    /// generated scalar is uniformly random and suitable for cryptographic operations.
    ///
    /// # Type Parameters
    ///
    /// - `R`: A type that implements both `RngCore` and `CryptoRng`, ensuring
    ///        cryptographic security of the random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator that implements
    ///           `RngCore` and `CryptoRng`.
    ///
    /// # Returns
    ///
    /// * `Scalar` - A randomly generated scalar suitable for use in Curve25519-based
    ///              cryptographic operations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    ///
    /// let mut rng = OsRng;
    /// let random_scalar = CryptoUtils::random_scalar(&mut rng);
    /// ```
    pub(crate) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    /// Hashes a Ristretto point to a byte vector of a specified length.
    ///
    /// This function takes a `RistrettoPoint` and produces a deterministic byte vector
    /// of the desired length by repeatedly hashing the compressed point concatenated
    /// with a counter using SHA-256. If the initial hash does not provide enough bytes,
    /// the counter is incremented, and the hashing process is repeated until the
    /// required length is achieved.
    ///
    /// # Arguments
    ///
    /// * `point` - A reference to the `RistrettoPoint` to be hashed.
    /// * `length` - The desired length of the output byte vector.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A byte vector containing the hashed output of the specified length.
    ///
    /// # Example
    ///
    /// ```rust
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    ///
    /// let point = RistrettoPoint::default();
    /// let hashed_bytes = CryptoUtils::hash_point_to_length(&point, 64);
    /// assert_eq!(hashed_bytes.len(), 64);
    /// ```
    pub(crate) fn hash_point_to_length(point: &RistrettoPoint, length: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let compressed = point.compress();
        let point_bytes = compressed.as_bytes();
        let mut output = Vec::with_capacity(length);

        // Keep hashing until we have enough bytes
        let mut counter = 0u64;
        while output.len() < length {
            hasher.update(point_bytes);
            hasher.update(&counter.to_le_bytes());
            let hash = hasher.finalize_reset();
            output.extend_from_slice(&hash);
            counter += 1;
        }

        // Truncate to exact length
        output.truncate(length);
        output
    }

    /// Performs a bitwise XOR operation on two byte slices of equal length.
    ///
    /// This function takes two slices of bytes (`a` and `b`) and returns a new `Vec<u8>`
    /// where each byte is the result of XOR-ing the corresponding bytes from `a` and `b`.
    /// It is crucial that both input slices are of the same length; otherwise, the function
    /// will trigger a debug assertion failure.
    ///
    /// # Arguments
    ///
    /// * `a` - A byte slice representing the first operand in the XOR operation.
    /// * `b` - A byte slice representing the second operand in the XOR operation.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - A vector containing the result of the XOR operation.
    ///
    /// # Panics
    ///
    /// This function will panic in debug mode if the lengths of `a` and `b` are not equal.
    ///
    /// # Example
    ///
    /// ```rust
    /// let a = vec![0xAA, 0xBB, 0xCC];
    /// let b = vec![0xFF, 0x00, 0xFF];
    /// let result = CryptoUtils::xor_bytes(&a, &b);
    /// assert_eq!(result, vec![0x55, 0xBB, 0x33]);
    /// ```
    pub(crate) fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        debug_assert_eq!(a.len(), b.len(), "XOR requires equal length inputs");
        a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
    }
}
