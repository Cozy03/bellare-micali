use bellare_micali::{Message, OTProtocol};
use rand::rngs::OsRng;
use test_case::test_case;

#[test]
fn test_complete_protocol_different_message_sizes() {
    let message_pairs = vec![
        (vec![0u8; 16], vec![1u8; 16]),    // 16 bytes
        (vec![0u8; 32], vec![1u8; 32]),    // 32 bytes
        (vec![0u8; 64], vec![1u8; 64]),    // 64 bytes
        (vec![0u8; 128], vec![1u8; 128]),  // 128 bytes
    ];

    for (msg0_data, msg1_data) in message_pairs {
        let mut rng = OsRng;
        
        // Initialize sender
        let sender = OTProtocol::new_sender(&mut rng);
        
        // Create messages
        let msg0 = Message::new(msg0_data.clone());  // Clone here
        let msg1 = Message::new(msg1_data.clone());  // Clone here
        
        // Test both choice bits
        for &choice in &[false, true] {
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
                assert_eq!(decrypted.as_bytes(), msg1_data.as_slice());
            } else {
                assert_eq!(decrypted.as_bytes(), msg0_data.as_slice());
            }
        }
    }
}

#[test_case(false ; "when choosing first message")]
#[test_case(true ; "when choosing second message")]
fn test_protocol_with_empty_messages(choice: bool) {
    let mut rng = OsRng;
    let sender = OTProtocol::new_sender(&mut rng);
    
    let msg0 = Message::new(vec![]);
    let msg1 = Message::new(vec![]);
    
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
    assert_eq!(decrypted.as_bytes(), &[]);
}

#[test]
fn test_invalid_public_keys() {
    let mut rng = OsRng;
    let sender = OTProtocol::new_sender(&mut rng);
    let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    
    // Generate valid keys first
    let (pk0, _) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    
    // Create another receiver to get an invalid key
    let receiver2 = OTProtocol::new_receiver(&mut rng, false, sender.c);
    let (pk2, _) = OTProtocol::receiver_generate_keys(&receiver2, sender.c);
    
    // Try to encrypt with invalid key combination
    let msg0 = Message::new(vec![1, 2, 3]);
    let msg1 = Message::new(vec![4, 5, 6]);
    
    let result = OTProtocol::sender_encrypt(
        &mut rng,
        &sender,
        pk0,
        pk2,  // This key is from a different receiver
        &msg0,
        &msg1,
    );
    
    assert!(result.is_err());
}