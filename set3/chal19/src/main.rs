extern crate rustc_serialize as serialize;
extern crate openssl;

use serialize::base64::FromBase64;
use serialize::hex::ToHex;

use std::mem::transmute;

use std::process;
use std::str;
use std::env;

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

fn repeat_xor(s: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
	let mut out: Vec<u8> = Vec::new();
	let key_len = key.len();
	for i in 0..s.len() {
		out.push(s[i] ^ key[i % key_len]);
	}
	out
}

fn aes_128_ctr_mode(s: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Vec<u8> {
	let mut block_size = 16;
	let mut block_count: u64 = 0;
	let mut crypted_count = 0;
	let mut all_cryted = Vec::new();
	while crypted_count < s.len() {
		let len_diff = s.len() - crypted_count;
		if len_diff < block_size {
			block_size = len_diff;
		}
		let mut stream_unencrypted = Vec::new();
		stream_unencrypted.extend(nonce);
		let nonce_bytes: [u8;8] = unsafe{ transmute(block_count.to_le()) };
		stream_unencrypted.extend(nonce_bytes.to_vec());
		let stream = encrypt_block(&key, &stream_unencrypted);
		let decrypted = repeat_xor(&stream[0..block_size].to_vec(), &s[crypted_count..crypted_count + block_size].to_vec());
		crypted_count += block_size;
		block_count += 1;
		all_cryted.extend(decrypted);
	}
	all_cryted
}

fn main() {
	let args: Vec<String> = env::args().collect();
	if args.len() < 3 {
		println!("No argument provided - run as ./chal1 $base64_encrypted_string $key");
		process::exit(1);
	}
	let encrypted = args[1].from_base64().unwrap();
	let key = args[2].as_bytes().to_vec();
    println!("Hex Input: {}", encrypted.to_hex());
	println!("Key: {}", key.to_hex());
	let nonce = [0;8].to_vec();
	let decrypted = aes_128_ctr_mode(&encrypted, &key, &nonce);
	println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
