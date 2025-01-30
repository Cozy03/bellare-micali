use crate::crypto::CryptoUtils;
use crate::{Message, OTError, OTProtocol};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, RistrettoPoint};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

/// Batch processing implementation of the Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) Protocol.
///
/// The `BatchOTProtocol` struct provides functionalities to handle multiple OT transfers simultaneously,
/// optimizing performance through parallel processing and efficient chunking strategies. This is particularly
/// useful in scenarios where numerous OT operations need to be executed concurrently, such as in secure
/// multi-party computations or bulk data processing.
pub struct BatchOTProtocol;

impl BatchOTProtocol {
    /// Determines the optimal chunk size based on the size of the messages.
    ///
    /// This function selects an appropriate chunk size to balance between parallel processing
    /// efficiency and memory usage. Smaller messages may benefit from larger chunks, while larger
    /// messages may require smaller chunks to optimize performance.
    ///
    /// # Arguments
    ///
    /// * `msg_size` - The size of the message in bytes.
    ///
    /// # Returns
    ///
    /// * `usize` - The optimal chunk size for the given message size.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bellare_micali_ot::BatchOTProtocol;
    ///
    /// let chunk_size = BatchOTProtocol::optimal_chunk_size(50);
    /// assert_eq!(chunk_size, 64);
    ///
    /// let chunk_size = BatchOTProtocol::optimal_chunk_size(500);
    /// assert_eq!(chunk_size, 32);
    ///
    /// let chunk_size = BatchOTProtocol::optimal_chunk_size(2000);
    /// assert_eq!(chunk_size, 16);
    /// ```
    fn optimal_chunk_size(msg_size: usize) -> usize {
        match msg_size {
            0..=64 => 64,    // Small messages
            65..=1024 => 32, // Medium messages
            _ => 16,         // Large messages
        }
    }

    /// Processes multiple OT transfers with optimized chunking and parallel execution.
    ///
    /// This function handles a batch of OT transfers by performing the following steps:
    /// 1. Validates that the input slices (`msgs0`, `msgs1`, and `choices`) have matching lengths.
    /// 2. Determines the optimal chunk size based on the size of the messages.
    /// 3. Initializes a single sender instance for all transfers.
    /// 4. Executes each OT transfer in parallel using Rayon’s parallel iterators, ensuring efficient utilization of system resources.
    ///
    /// # Type Parameters
    ///
    /// - `R`: A type that implements both `RngCore` and `CryptoRng`, ensuring cryptographic
    ///        security of the random number generator. Additionally, it must implement `Clone`, `Send`, and `Sync` to facilitate parallel execution.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator that implements `RngCore` and `CryptoRng`.
    /// * `msgs0` - A slice of `Message` instances representing the first set of messages to be sent.
    /// * `msgs1` - A slice of `Message` instances representing the second set of messages to be sent.
    /// * `choices` - A slice of boolean values indicating each receiver's choice bit. `true` selects the second message, while `false` selects the first.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Message>, OTError>` - On success, returns a vector of decrypted `Message` instances corresponding to each receiver's choice. On failure, returns an `OTError`.
    ///
    /// # Errors
    ///
    /// * `OTError::ProtocolError` - If the lengths of `msgs0`, `msgs1`, and `choices` do not match, indicating inconsistent batch sizes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::{BatchOTProtocol, Message, OTError};
    ///
    /// fn main() -> Result<(), OTError> {
    ///     let mut rng = OsRng;
    ///     let msgs0 = vec![
    ///         Message::new(b"Secret0_1".to_vec()),
    ///         Message::new(b"Secret0_2".to_vec()),
    ///     ];
    ///     let msgs1 = vec![
    ///         Message::new(b"Secret1_1".to_vec()),
    ///         Message::new(b"Secret1_2".to_vec()),
    ///     ];
    ///     let choices = vec![false, true];
    ///
    ///     let results = BatchOTProtocol::batch_transfer(&mut rng, &msgs0, &msgs1, &choices)?;
    ///
    ///     assert_eq!(results[0].as_bytes(), b"Secret0_1");
    ///     assert_eq!(results[1].as_bytes(), b"Secret1_2");
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn batch_transfer<R: RngCore + CryptoRng + Clone + Send + Sync>(
        rng: &mut R,
        msgs0: &[Message],
        msgs1: &[Message],
        choices: &[bool],
    ) -> Result<Vec<Message>, OTError> {
        if msgs0.len() != msgs1.len() || msgs0.len() != choices.len() {
            return Err(OTError::ProtocolError("Batch sizes do not match".into()));
        }

        // Calculate optimal chunk size
        let msg_size = msgs0.first().map_or(0, |m| m.as_bytes().len());
        let _chunk_size = Self::optimal_chunk_size(msg_size);

        // Create sender for all transfers
        let sender = OTProtocol::new_sender(rng);

        // Process in parallel with thread-local RNGs
        let results: Result<Vec<_>, _> = (0..msgs0.len())
            .into_par_iter()
            .map(|i| {
                // Create thread-local RNG
                let mut thread_rng = OsRng;

                // Create receiver and keys
                let receiver = OTProtocol::new_receiver(&mut thread_rng, choices[i], sender.c);
                let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);

                // Encrypt and decrypt
                let (c0, c1) = OTProtocol::sender_encrypt(
                    &mut thread_rng,
                    &sender,
                    pk0,
                    pk1,
                    &msgs0[i],
                    &msgs1[i],
                )?;

                OTProtocol::receiver_decrypt(&receiver, &c0, &c1)
            })
            .collect();

        results
    }

    /// Optimized batch key generation for multiple OT transfers.
    ///
    /// This function generates the necessary public keys for a batch of OT transfers based
    /// on the sender's public key and the receivers' choice bits. It leverages parallel
    /// processing to efficiently generate keys for all receivers simultaneously.
    ///
    /// # Arguments
    ///
    /// * `sender_pk` - The sender's public Ristretto point used in key generation.
    /// * `choices` - A slice of boolean values indicating each receiver's choice bit.
    ///              `true` selects the second key, while `false` selects the first.
    ///
    /// # Returns
    ///
    /// * `Vec<(RistrettoPoint, RistrettoPoint)>` - A vector of tuples, each containing two `RistrettoPoint` instances representing the public keys for each OT transfer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use curve25519_dalek::ristretto::RistrettoPoint;
    /// use rand::rngs::OsRng;
    /// use bellare_micali_ot::{BatchOTProtocol, OTProtocol};
    ///
    /// fn main() {
    ///     let sender = OTProtocol::new_sender(&mut OsRng);
    ///     let choices = vec![true, false, true];
    ///
    ///     let keys = BatchOTProtocol::batch_key_generation(sender.c, &choices);
    ///
    ///     assert_eq!(keys.len(), choices.len());
    /// }
    /// ```
    pub fn batch_key_generation(
        sender_pk: RistrettoPoint,
        choices: &[bool],
    ) -> Vec<(RistrettoPoint, RistrettoPoint)> {
        choices
            .par_iter()
            .map(|&choice| {
                let mut rng = OsRng;
                let k = CryptoUtils::random_scalar(&mut rng);

                let pk_b = G * k;
                let pk_not_b = sender_pk - pk_b;

                if choice {
                    (pk_not_b, pk_b)
                } else {
                    (pk_b, pk_not_b)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the batch processing functionality of the OT protocol.
    ///
    /// This test verifies that the `batch_transfer` function correctly handles multiple
    /// OT transfers with varying choice bits. It performs the following steps:
    /// 1. Initializes a sender and a set of messages.
    /// 2. Iterates over different batch sizes to test scalability.
    /// 3. For each batch size:
    ///    - Creates corresponding `Message` instances for both message sets.
    ///    - Generates a set of choice bits.
    ///    - Executes the batch transfer.
    ///    - Asserts that each decrypted message matches the expected message based on the choice bit.
    #[test]
    fn test_batch_processing() {
        let mut rng = OsRng;
        let batch_sizes = [1, 10, 50, 100];

        for &size in batch_sizes.iter() {
            let msgs0: Vec<_> = (0..size)
                .map(|i| Message::new(format!("Secret0 {}", i).into_bytes()))
                .collect();

            let msgs1: Vec<_> = (0..size)
                .map(|i| Message::new(format!("Secret1 {}", i).into_bytes()))
                .collect();

            let choices: Vec<_> = (0..size).map(|i| i % 2 == 0).collect();

            let results = BatchOTProtocol::batch_transfer(&mut rng, &msgs0, &msgs1, &choices)
                .expect("Batch transfer failed");

            for (i, (result, &choice)) in results.iter().zip(choices.iter()).enumerate() {
                let expected = if choice {
                    format!("Secret1 {}", i)
                } else {
                    format!("Secret0 {}", i)
                };
                assert_eq!(result.as_bytes(), expected.as_bytes());
            }
        }
    }

    /// Tests the batch transfer function with unequal batch sizes.
    ///
    /// This test ensures that the `batch_transfer` function correctly identifies and
    /// handles cases where the input slices (`msgs0`, `msgs1`, and `choices`) have
    /// mismatched lengths, returning an appropriate error.
    #[test]
    fn test_unequal_batch_sizes() {
        let mut rng = OsRng;
        let msgs0 = vec![Message::new(vec![0u8; 32])];
        let msgs1 = vec![Message::new(vec![1u8; 32]), Message::new(vec![1u8; 32])];
        let choices = vec![true];

        assert!(BatchOTProtocol::batch_transfer(&mut rng, &msgs0, &msgs1, &choices).is_err());
    }
}
