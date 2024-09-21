extern crate secp256k1;
extern crate rand;
extern crate hex;

use secp256k1::{Secp256k1, SecretKey, PublicKey};
use bitcoin_hashes::{sha256, ripemd160, Hash};
use rand::Rng;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

// Target RIPEMD160 hash (provided value)
const TARGET_RIPEMD160_HEX: &str = "739437bb3dd6d1983e66629c5f08c70e52769371";
const STARTING_HEX: &str = "0000000000000000000000000000000000000000000000040000000000000000";
const END_HEX: &str = "000000000000000000000000000000000000000000000007ffffffffffffffff";
const INCREMENT_COUNT: u32 = 1000000;
const THREAD_COUNT: usize = 28;

// Convert a hex string to a fixed-size byte array
fn hex_to_fixed_array(hex: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let hex_vec = hex::decode(hex).expect("Invalid hex string");
    bytes.copy_from_slice(&hex_vec);
    bytes
}

// Convert a hex string to a vector of bytes
fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("Invalid hex string")
}

// Check if the private key is within the specified range
fn is_within_range(seckey: &[u8; 32]) -> bool {
    let starting = hex_to_fixed_array(STARTING_HEX);
    let ending = hex_to_fixed_array(END_HEX);
    seckey >= &starting && seckey <= &ending
}

fn modify_private_key(seckey: &mut [u8; 32]) {
    let mut rng = rand::thread_rng();
    
    // Ensure we only modify from the first non-zero byte (ignoring leading zeros)
    let start_byte = seckey.iter().position(|&x| x != 0).unwrap_or(0);

    // Constrain the first byte to stay within the valid range [0x02, 0x03]
    if start_byte == 0 {
        seckey[0] = rng.gen_range(0x02..=0x03);
    }

    // Randomly modify bits in the rest of the bytes
    let byte_index = rng.gen_range(start_byte..32); // Random byte index starting from the non-zero byte
    let bit_index = rng.gen_range(0..8); // Random bit index (0-7)

    // Flip the selected bit
    seckey[byte_index] ^= 1 << bit_index;
}

fn increment_private_key(seckey: &mut [u8; 32]) {
    let mut carry = true;
    for byte in seckey.iter_mut().rev() {
        if carry {
            let (new_byte, did_overflow) = byte.overflowing_add(1);
            *byte = new_byte;
            carry = did_overflow;
        } else {
            break;
        }
    }
}

fn search_for_key(
    thread_id: usize,
    secp: Arc<Secp256k1<secp256k1::All>>,
    target_ripemd160_bytes: Vec<u8>, // Target RIPEMD160 hash
    found: Arc<AtomicBool>,
    shared_key: Arc<Mutex<Option<[u8; 32]>>>,
) {
    let mut seckey_bytes = hex_to_fixed_array(STARTING_HEX);

    loop {
        // Check if another thread has already found the key
        if found.load(Ordering::Relaxed) {
            break;
        }

        // Modify the private key randomly
        modify_private_key(&mut seckey_bytes);
        if !is_within_range(&seckey_bytes) {
            continue; // Skip if out of range
        }

        let seckey = SecretKey::from_slice(&seckey_bytes).expect("32 bytes, within curve order");
        let pubkey = PublicKey::from_secret_key(&secp, &seckey);
        let pubkey_bytes = pubkey.serialize();

        // Calculate the SHA256 hash of the public key
        let sha256_hash = sha256::Hash::hash(&pubkey_bytes);

        // Calculate the RIPEMD160 hash of the SHA256 result
        let ripemd160_hash = ripemd160::Hash::hash(&sha256_hash);

        // Print the private key, public key, SHA256, and RIPEMD160 hashes
        println!(
            "{} , {}",
            hex::encode(&seckey_bytes),
            hex::encode(ripemd160_hash)
        );

        // Check if the generated RIPEMD160 hash matches the target RIPEMD160 hash
        if ripemd160_hash[..] == target_ripemd160_bytes[..] {
            println!("Thread {} found a match! Private Key: {}", thread_id, hex::encode(&seckey_bytes));

            // Save the key and mark found
            {
                let mut shared_key_guard = shared_key.lock().unwrap();
                *shared_key_guard = Some(seckey_bytes);
            }
            found.store(true, Ordering::Relaxed);
            break;
        }

        // Perform increments and check each public key
        for _ in 0..INCREMENT_COUNT {
            increment_private_key(&mut seckey_bytes);
            if !is_within_range(&seckey_bytes) {
                break; // Stop if out of range
            }

            let seckey = SecretKey::from_slice(&seckey_bytes).expect("32 bytes, within curve order");
            let pubkey = PublicKey::from_secret_key(&secp, &seckey);
            let pubkey_bytes = pubkey.serialize();

            // Check if another thread found the key
            if found.load(Ordering::Relaxed) {
                break;
            }

            // Calculate the SHA256 and RIPEMD160 hashes for the new public key
            let sha256_hash = sha256::Hash::hash(&pubkey_bytes);
            let ripemd160_hash = ripemd160::Hash::hash(&sha256_hash);

            // Check if this thread found the key
            if ripemd160_hash[..] == target_ripemd160_bytes[..] {
                println!("Thread {} found a match during increment! Private Key: {}", thread_id, hex::encode(&seckey_bytes));

                // Save the key and mark found
                {
                    let mut shared_key_guard = shared_key.lock().unwrap();
                    *shared_key_guard = Some(seckey_bytes);
                }
                found.store(true, Ordering::Relaxed);
                break;
            }
        }
    }
}

// Save the private key to a file
fn save_private_key_to_file(private_key: &[u8; 32]) {
    let mut file = File::create("found_key.txt").expect("Could not create file");
    let private_key_hex = hex::encode(private_key);
    file.write_all(private_key_hex.as_bytes()).expect("Failed to write private key to file");
    println!("Private key saved to 'found_key.txt'.");
}

fn main() {
    let secp = Arc::new(Secp256k1::new());
    let target_ripemd160_bytes = hex_to_vec(TARGET_RIPEMD160_HEX); // Target RIPEMD160 hash
    let found = Arc::new(AtomicBool::new(false));
    let shared_key: Arc<Mutex<Option<[u8; 32]>>> = Arc::new(Mutex::new(None));

    // Spawn threads
    let mut handles = vec![];

    for i in 0..THREAD_COUNT {
        let secp = Arc::clone(&secp);
        let target_ripemd160_bytes = target_ripemd160_bytes.clone();
        let found = Arc::clone(&found);
        let shared_key = Arc::clone(&shared_key);

        let handle = thread::spawn(move || {
            search_for_key(i, secp, target_ripemd160_bytes, found, shared_key);
        });

        handles.push(handle);
    }

    // Wait for all threads to finish
    for handle in handles {
        handle.join().unwrap();
    }

    // If found, save the key to a file
    if let Some(seckey) = *shared_key.lock().unwrap() {
        save_private_key_to_file(&seckey);
    } else {
        println!("No matching private key found.");
    };
}
