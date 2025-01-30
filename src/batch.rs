use crate::{Message, OTError, OTProtocol};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

/// Batch processing implementation of the Bellare-Micali 1-out-of-2 Oblivious Transfer (OT) Protocol.
///
/// The `BatchOTProtocol` struct provides functionalities to handle multiple OT transfers simultaneously,
/// optimizing performance through parallel processing and efficient chunking strategies.
pub struct BatchOTProtocol;

impl BatchOTProtocol {
    /// Determines the optimal chunk size based on the size of the messages.
    ///
    /// This function selects an appropriate chunk size to balance between parallel processing
    /// efficiency and memory usage.
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
    /// use bellare_micali::BatchOTProtocol;
    ///
    /// let chunk_size = BatchOTProtocol::optimal_chunk_size(50);
    /// assert_eq!(chunk_size, 64);
    /// ```
    pub fn optimal_chunk_size(msg_size: usize) -> usize {
        match msg_size {
            0..=64 => 64,    // Small messages
            65..=1024 => 32, // Medium messages
            _ => 16,         // Large messages
        }
    }

    /// Processes multiple OT transfers with optimized chunking and parallel execution.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to a random number generator.
    /// * `msgs0` - First set of messages.
    /// * `msgs1` - Second set of messages.
    /// * `choices` - A slice of boolean values representing selection choices.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Message>, OTError>` - The decrypted messages.
    ///
    /// # Errors
    ///
    /// * `OTError::ProtocolError` - If batch sizes do not match.
    pub fn batch_transfer<R: RngCore + CryptoRng + Clone + Send + Sync>(
        rng: &mut R,
        msgs0: &[Message],
        msgs1: &[Message],
        choices: &[bool],
    ) -> Result<Vec<Message>, OTError> {
        if msgs0.len() != msgs1.len() || msgs0.len() != choices.len() {
            return Err(OTError::ProtocolError("Batch sizes do not match".into()));
        }

        let sender = OTProtocol::new_sender(rng);

        let results: Result<Vec<_>, _> = (0..msgs0.len())
            .into_par_iter()
            .map(|i| {
                let mut thread_rng = OsRng;
                let receiver = OTProtocol::new_receiver(&mut thread_rng, choices[i], sender.c);
                let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimal_chunk_size() {
        assert_eq!(BatchOTProtocol::optimal_chunk_size(50), 64);
        assert_eq!(BatchOTProtocol::optimal_chunk_size(500), 32);
        assert_eq!(BatchOTProtocol::optimal_chunk_size(2000), 16);
    }
}
