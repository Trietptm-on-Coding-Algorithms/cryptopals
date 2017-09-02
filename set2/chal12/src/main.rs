extern crate rustc_serialize as serialize;
extern crate openssl;
extern crate rand;

use serialize::base64::FromBase64;
use std::collections::HashMap;

use std::process;
use std::str;

fn random_aes_key() -> Vec<u8> {
	let mut out: Vec<u8> = Vec::new();
	for _ in 0..16 {
		let byte = rand::random::<u8>();
		out.push(byte);
	}
	out
}

fn encrypt_block(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
	let cipher = openssl::symm::Cipher::aes_128_ecb();
	let result = match openssl::symm::encrypt(cipher, &key, None, &data) {
		Ok(data) => data,
		Err(e) => {
			println!("Failed to encrypt data: {}", e);
			process::exit(1);
		}
	};
	result
}

fn detect_ecb_mode(data: &Vec<u8>) -> bool {
	let block_size = 16;
	let mut out = false;
	let block_count = data.len() / block_size;
	let mut counts = HashMap::new();
	for i in 0..block_count {
		let entry: Vec<u8> = data[i*block_size..(i*block_size) + block_size].to_vec();
		let count = counts.entry(entry).or_insert(0);
		*count += 1;
	}
	for (_, count) in counts {
		if count > 1 {
			out = true;
			break;
		}
	}
	out
}

fn detect_mode(data: &Vec<u8>) -> &str {
	let out;
	if detect_ecb_mode(data) {
		out = "ECB";
	} else {
		out = "CBC";
	}
	out
}

fn ecb_oracle(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
	let secret_message = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".from_base64();
	let mut to_encrypt: Vec<u8> = Vec::new();
	to_encrypt.extend(data);
	to_encrypt.extend(secret_message.unwrap());
	let encrypted = encrypt_block(key, &to_encrypt);
	encrypted
}

fn main() {
	//Input just needs to be big enough to garuntee we fill two blocks entirely with out data
	//in ECB mode this will produce two matching blocks, in CBC they will differ.
    let key = random_aes_key();
	let mut input: Vec<u8> = Vec::new();
	let out = ecb_oracle(&key, &input);
	let start_len = out.len();
	let mut end_len;
	loop {
		input.push(0x41);
		let out = ecb_oracle(&key, &input);
		println!("Output length: {}", out.len());
		end_len = out.len();
		if end_len != start_len {
			break;
		}
	}
	let block_size = end_len - start_len;
	let block_count = start_len / block_size;
	println!("Found block size: {}", block_size);
	println!("Detecting if cipher mode is ecb by submitting input with len 2 * block_size and validating repeating blocks found");
	let mut mode_detect: Vec<u8> = Vec::new();
	for _ in 0..block_size * 2 {
		mode_detect.push(0x41);
	}
	let out = ecb_oracle(&key, &mode_detect);
	let mode = detect_mode(&out);
	println!("Mode: {}", mode);
	if mode != "ECB" {
		println!("Encryption Oracle is not ECB mode :(");
		process::exit(1);
	}
	println!("{} Blocks to decrypt!", block_count);
	let mut found: Vec<u8> = Vec::new();
	for i in 0..block_size {
		let mut mappings = HashMap::new();
		let mut finger_print_blocks: Vec<u8> = Vec::new();
		for _ in 1..(block_size - i) {
			finger_print_blocks.push(0x41);
		}
		
		finger_print_blocks.extend(&found);
		for byte in 0..255 {
			let mut test: Vec<u8> = Vec::new();
			test.extend(&finger_print_blocks);
			test.push(byte);
			let out = ecb_oracle(&key, &test);
			mappings.insert(out[0..(block_size as usize)].to_vec(), test);
		}
		let mut finger_print_blocks: Vec<u8> = Vec::new();
		for _ in 1..(block_size - i) {
			finger_print_blocks.push(0x41);
		}
		let out = ecb_oracle(&key, &finger_print_blocks);
		let decoded = mappings.get(&out[0..(block_size as usize)].to_vec()).unwrap();
		let val = decoded[block_size - 1];
		println!("Decoded a character: {}", val);
		found.push(val);
	}
	println!("First block: {}", String::from_utf8_lossy(&found));
	for block_num in 0..(block_count - 1){
		for i in 0..block_size{
			let mut mappings = HashMap::new();
			let mut finger_print_blocks: Vec<u8> = Vec::new();	
			finger_print_blocks.extend(&found[1 + (block_num * block_size)+ i..((block_num + 1) * block_size) + i]);
			for byte in 0..255 {
				let mut test: Vec<u8> = Vec::new();
				test.extend(&finger_print_blocks);
				test.push(byte);
				let out = ecb_oracle(&key, &test);
				mappings.insert(out[0..(block_size as usize)].to_vec(), test);
			}
			let mut finger_print_blocks: Vec<u8> = Vec::new();
			for _ in 1..(block_size - i) {
				finger_print_blocks.push(0x41);
			}
			let out = ecb_oracle(&key, &finger_print_blocks);
			let decoded = match mappings.get(&out[((block_num + 1) * block_size as usize)..((block_num + 2) * block_size as usize)].to_vec()) {
				Some(char) => char,
				None => {
					println!("Character not recovered - may be end of message!");
					println!("Another block decoded: {}", String::from_utf8_lossy(&found));
					process::exit(0);
				}
			};
			let val = decoded[block_size - 1];
			println!("Decoded character: {}", val);
			found.push(val);
		}
		println!("Another block decoded: {}", String::from_utf8_lossy(&found));
	}
}
