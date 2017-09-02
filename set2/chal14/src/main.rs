extern crate rustc_serialize as serialize;
extern crate openssl;
extern crate rand;

use serialize::base64::FromBase64;
use std::collections::HashMap;

use rand::distributions::{IndependentSample, Range};

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
	let between = Range::new(5, 10);
	let mut rng = rand::thread_rng();
	let prepend_pad_len = between.ind_sample(&mut rng);
	let mut prepend_pad: Vec<u8> = Vec::new();
	for _ in 0..prepend_pad_len {
		let byte = rand::random::<u8>();
		prepend_pad.push(byte);
	}
	let mut to_encrypt: Vec<u8> = Vec::new();
	to_encrypt.extend(prepend_pad);
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
	println!("Detecting if cipher mode is ecb by submitting input with len 4 * block_size and validating repeating blocks found");
	//4 * block size is required we have unknown lengths on both ends, this means two middle blocks should always be intact though
	let mut mode_detect: Vec<u8> = Vec::new();
	for _ in 0..block_size * 4 {
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
}
