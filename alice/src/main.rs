use std::net::TcpStream;
use std::io::{prelude::*,BufReader,Write};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::{GenericArray, typenum::U48},
};
use openssl::rand::rand_bytes;
use rand::Rng;

fn main() {
    // Connect to the socket bound at localhost port 6969
    let mut stream = TcpStream::connect("127.0.0.1:6969").expect("Failed to connect");
    println!("\nConnected to localhost:6969...\n");
    // Initialize r as a fixed 48-byte array
    let mut r = GenericArray::from([0u8; 48]);
    // Generate the value of r using openssl's pseudorandom generator
    rand_bytes(&mut r).unwrap();
    println!("Generated r: {}", hex::encode(r));
    // Generate the value of Alice's bit b1 using a CSPRNG
    let alice_bit = rand::thread_rng().gen_range(0..=1);
    println!("\nGenerated Alice's bit (b1): {}", &alice_bit);
    // Initialize and populate the byte vector containing the data to be sent to the server Bob
    let mut alice_sends_bob = r.to_vec();
    alice_sends_bob.push(alice_bit);
    println!("\nSending (r, b1) to Bob...\n");
    // Send the hex-encoded data stream to the server
    stream.write_all(hex::encode(alice_sends_bob).as_bytes()).expect("failed to write");
    // Refresh the data stream for accepting data from Bob
    let stream = TcpStream::connect("127.0.0.1:6969").expect("Failed to connect");
    // Initialize buffered reader to receive data from the server
    let mut reader = BufReader::new(&stream);
    let mut buffer: Vec<u8> = Vec::new();
    // Read the data stream from server until the newline escape literal
    reader.read_until(b'\n',&mut buffer).unwrap();
    // Decode the hex-encoded buffer of data
    let decoded_hex = hex::decode(buffer).unwrap();
    // Extract the opening string received in the data stream from the server Bob
    let opening_string = GenericArray::from_slice(&decoded_hex[0..=15]);
    // Extract the key received in the data stream from the server Bob
    let key = GenericArray::from_slice(&decoded_hex[16..=31]);
    // Extract the committed bit received in the data stream from the server Bob
    let commitment_string: GenericArray<_, U48> = *GenericArray::from_slice(&decoded_hex[32..=79]);
    println!("Received (s, k, c) from Bob: {}, {}, {}", hex::encode(opening_string), hex::encode(key), hex::encode(commitment_string));
    // Initialize the cipher under the same key as Bob's that was received from the server
    let cipher = Aes128::new(key);
    // Perform three rounds of AES encryption in OFB mode to obtain the PRG output
    let message = GenericArray::from([0u8; 48]);
    let mut block = *opening_string;
    // AES encrypt the block using the given key
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
    // Calculate Bob's committed bit depending on whether ciphertext equals commitment_string
    let committed_bit = u8::from(!hex::encode(&ciphertext).eq(&hex::encode(commitment_string)));
    // Compute the commitment string using the com(s, r, b0) piecewise function for verification
    let commitment_string_computed: Vec<u8> = if committed_bit == 0 {
        ciphertext
    } else {
        // Compute G(s) XOR r
        ciphertext
            .iter()
            .zip(r.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect()
    };
    println!("\nCommitment string computed by Alice for verification (c'): {}", hex::encode(&commitment_string_computed));
    if hex::encode(&commitment_string_computed).eq(&hex::encode(commitment_string)) {
        println!("\nVerification success!");
        println!("\nFinal output bit (b) = Bob's committed bit (b0) XOR Alice's bit (b1) = {}", committed_bit ^ alice_bit);
    } else {
        println!("Verification failure!!");
    }
    println!("\nConnection terminated.");
}
