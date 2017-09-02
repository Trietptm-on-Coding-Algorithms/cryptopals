extern crate rustc_serialize as serialize;
extern crate openssl;
extern crate rand;

use std::collections::HashMap;
use serialize::hex::ToHex;

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

fn encrypt_cbc(key: &Vec<u8>,iv: &Vec<u8> ,data: &Vec<u8>) -> Vec<u8> { 
	let mut encrypted_all: Vec<u8> = Vec::new();
	let block_size = 16;
	let block_count = data.len() / block_size;
	let mut prev_block: Vec<u8> = iv.to_vec();
	for i in 0..block_count {
		let block = data[(block_size * i)..((block_size * i) + block_size)].to_vec();
		let mut xord: Vec<u8> = Vec::new();
		for i in 0..16 {
			xord.push(block[i] ^ prev_block[i]);
		}
		let encrypted = encrypt_block(key, &xord)[0..16].to_vec();
		encrypted_all.extend(&encrypted);
		prev_block = encrypted;
	}
	encrypted_all
}

fn encryption_oracle(data: &Vec<u8>) -> Vec<u8> {
	let key = random_aes_key();
	let out;
	let between = Range::new(5, 10);
	let mut rng = rand::thread_rng();
	let start_pad_len = between.ind_sample(&mut rng);
	let end_pad_len = between.ind_sample(&mut rng);
	let mut start_pad: Vec<u8> = Vec::new();
	for _ in 0..start_pad_len {
		let byte = rand::random::<u8>();
		start_pad.push(byte);
	}
	let mut end_pad: Vec<u8> = Vec::new();
	for _ in 0..end_pad_len {
		let byte = rand::random::<u8>();
		end_pad.push(byte);
	}
	start_pad.extend(data);
	start_pad.extend(end_pad);
	if rand::random::<bool>() {
		let iv = random_aes_key();
		out = encrypt_cbc(&key, &iv, &start_pad);
	} else {
		out = encrypt_block(&key, &start_pad);
	}
	out
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
		out = "ECB Mode";
	} else {
		out = "CBC Mode";
	}
	out
}

fn main() {
	//Input just needs to be big enough to garuntee we fill two blocks entirely with out data
	//in ECB mode this will produce two matching blocks, in CBC they will differ.
	let input: [u8; 48] = [0x41; 48];
    for _ in 0..5{
		let data = encryption_oracle(&input.to_vec());
		let mode = detect_mode(&data);
		println!("Oracle output: {}, {}", data.to_hex(), mode);
	}
}
