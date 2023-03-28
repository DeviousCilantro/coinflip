use std::io::{Read, Write};
use std::net::TcpListener;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};
use openssl::rand::rand_bytes;
use rand::Rng;

pub fn main() {
    // Bind the socket to localhost port 6969
    let receiver_listener = TcpListener::bind("127.0.0.1:6969").expect("Failed and bind with the sender");
    println!("\nListening on localhost:6969...\n");
    // Initialize the data stream for listening to incoming connections
    let mut stream = receiver_listener.accept().unwrap().0;
    // Generate the committed bit b0 using a CSPRNG
    let committed_bit = rand::thread_rng().gen_range(0..=1);
    // Initialize the opening string as a fixed 16-byte array
    let mut opening_string = GenericArray::from([0u8; 16]);
    // Initialize the key as a fixed 16-byte array
    let mut key = GenericArray::from([0u8; 16]);
    // Generate the value of the openingstring using openssl's pseudorandom generator
    rand_bytes(&mut opening_string).unwrap();
    // Generate the value of key using openssl's pseudorandom generator
    rand_bytes(&mut key).unwrap();
    println!("Generated Bob's committed bit (b0): {}", &committed_bit);
    println!("\nGenerated opening string (s): {}", hex::encode(opening_string));
    println!("\nGenerated key (k): {}", hex::encode(key));
    // Initialize the buffer for handling data streams 
    let mut buf = [0; 512];
    // Write the data stream received from the client into the buffer
    let bytes_read = stream.read(&mut buf).unwrap();
    stream.write_all(&buf[..bytes_read]).unwrap();
    // Decode the relevant portion of the hex string into a byte vector
    let r = hex::decode(String::from_utf8_lossy(&buf).into_owned()[0..96].to_string()).unwrap();
    // Extract the portion of the hex string corresponding to Alice's bit
    let alice_bit = hex::decode(String::from_utf8_lossy(&buf).into_owned()[96..98].to_string()).unwrap()[0];
    println!("\nReceived (r, b1) from Alice: {}, {alice_bit}", hex::encode(&r));
    // Initialize the cipher under the generated key using the AES-128 primitive
    let cipher = Aes128::new(&key);
    // Perform three rounds of AES encryption in OFB mode to obtain the PRG output
    let message = GenericArray::from([0u8; 48]);
    let mut block = opening_string;
    cipher.encrypt_block(&mut block);
    // Compute block XOR (the first 16 bytes of message)
    let c1: Vec<u8> = block
        .iter()
        .zip(message[0..16].iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    // AES encrypt the block using the given key
    cipher.encrypt_block(&mut block);
    // Compute block XOR (the next 16 bytes of message)
    let c2: Vec<u8> = block
        .iter()
        .zip(message[16..32].iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    // AES encrypt the block using the given key
    cipher.encrypt_block(&mut block);
    // Compute block XOR (the last 16 bytes of message)
    let c3: Vec<u8> = block
        .iter()
        .zip(message[32..].iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect();
    // Compute the ciphertext as a concatenation of (c1, c2, c3)
    let ciphertext = [&c1[..], &c2[..], &c3[..]].concat();
    // Compute the commitment string using the com(s, r, b0) piecewise function
    let mut commitment_string: Vec<u8> = if committed_bit == 0 {
        println!("\nb0 = 0 => commitment_string = G(s)");
        ciphertext
    } else {
        println!("\nb0 = 1 => commitment_string = G(s) XOR r");
        // Compute G(s) XOR r
        ciphertext
            .iter()
            .zip(r.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect()
    };
    println!("\nCommitment string computed by Bob (c): {}", hex::encode(&commitment_string));
    // Refresh the data stream for sending the data to Alice
    let mut stream = receiver_listener.accept().unwrap().0;
    // Initialize and populate the byte vector containing the data to be sent to the client Alice
    let mut bob_sends_alice = opening_string.to_vec();
    bob_sends_alice.append(&mut key.to_vec());
    bob_sends_alice.append(&mut commitment_string);
    println!("\nSending (s, k, c) to Alice...\n");
    // Send the hex-encoded data stream to the client
    stream.write_all(hex::encode(&bob_sends_alice).as_bytes()).expect("failed to write");
    println!("Final output bit (b) = Bob's committed bit (b0) XOR Alice's bit (b1) = {}", committed_bit ^ alice_bit);
    println!("\nConnection terminated.");
}
