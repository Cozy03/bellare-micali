use bellare_micali::{Message, OTProtocol};
use rand::rngs::OsRng;

fn main() {
    // Initialize RNG
    let mut rng = OsRng;
    
    // Initialize sender
    let sender = OTProtocol::new_sender(&mut rng);
    println!("Sender initialized");
    
    // Create test messages
    let msg0 = Message::new(b"First secret message".to_vec());
    let msg1 = Message::new(b"Second secret message".to_vec());
    
    // Initialize receiver with choice bit (true = 1, false = 0)
    let choice_bit = true;
    let receiver = OTProtocol::new_receiver(&mut rng, choice_bit, sender.c);
    println!("Receiver initialized with choice bit {}", choice_bit);
    
    // Generate receiver's keys
    let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    println!("Receiver keys generated");
    
    // Sender encrypts messages
    let (c0, c1) = OTProtocol::sender_encrypt(
        &mut rng,
        &sender,
        pk0,
        pk1,
        &msg0,
        &msg1,
    ).expect("Encryption failed");
    println!("Messages encrypted");
    
    // Receiver decrypts chosen message
    let decrypted = OTProtocol::receiver_decrypt(&receiver, &c0, &c1)
        .expect("Decryption failed");
    println!("Decrypted message: {:?}", String::from_utf8_lossy(decrypted.as_bytes()));
}
