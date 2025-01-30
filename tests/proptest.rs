use bellare_micali::{Message, OTProtocol};
use proptest::prelude::*;
use rand::rngs::OsRng;

proptest! {
    #[test]
    fn test_arbitrary_messages(
        msg0 in prop::collection::vec(any::<u8>(), 0..1024),
        msg1 in prop::collection::vec(any::<u8>(), 0..1024),
        choice in prop::bool::ANY
    ) {
        let mut rng = OsRng;
        let sender = OTProtocol::new_sender(&mut rng);
        
        let msg0 = Message::new(msg0.clone());
        let msg1 = Message::new(msg1.clone());
        
        let receiver = OTProtocol::new_receiver(&mut rng, choice, sender.c);
        let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
        
        let (c0, c1) = OTProtocol::sender_encrypt(
            &mut rng,
            &sender,
            pk0,
            pk1,
            &msg0,
            &msg1,
        ).unwrap();
        
        let decrypted = OTProtocol::receiver_decrypt(&receiver, &c0, &c1).unwrap();
        
        if choice {
            prop_assert_eq!(decrypted.as_bytes(), msg1.as_bytes());
        } else {
            prop_assert_eq!(decrypted.as_bytes(), msg0.as_bytes());
        }
    }
}
