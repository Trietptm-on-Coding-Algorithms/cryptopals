extern crate rustc_serialize as serialize;
extern crate openssl as openssl;

use serialize::base64::FromBase64;
use serialize::base64::ToBase64;
use serialize::base64::STANDARD;

use serialize::hex::ToHex;
use serialize::hex::FromHex;

use std::env;
use std::process;
use std::str;

use std::fs::File;
use std::io::Read;

fn decrypt_block(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
	let cipher = openssl::symm::Cipher::aes_128_ecb();
	let mut crypter = match openssl::symm::Crypter::new(cipher,openssl::symm::Mode::Decrypt, key, None){
		Ok(crypter) => crypter,
		Err(e) => {
			println!("Failed to initialize crypter: {}", e);
			process::exit(1);
		}
	};
	crypter.pad(false);
	let mut out: [u8; 32] = [0; 32];
	crypter.update(data, &mut out);
	out.to_vec()
}

fn encrypt_block(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
	let cipher = openssl::symm::Cipher::aes_128_ecb();
	let result = match openssl::symm::encrypt(cipher, &key, None, &data) {
		Ok(data) => data,
		Err(e) => {
			println!("Failed to decrypt file: {}", e);
			process::exit(1);
		}
	};
	result
}

fn main() {
    let args: Vec<String> = env::args().collect();

	if args.len() < 3 {
		println!("No argument provided - run as ./chal7 $input_file $key");
		process::exit(1);
	}
	let mut f = match File::open(&args[1]) {
		Ok(file) => file,
		Err(e) => {
			println!("Failed to open file: {}", e);
			process::exit(1);
		}
	};
	let mut contents = String::new();
    f.read_to_string(&mut contents).expect("Failed to read input file.");
	let s = contents.from_base64().unwrap();
	println!("Input as hex: {}", s.to_hex());
	println!("Using key: {}", args[2]);
	let key = args[2].as_bytes().to_vec();
	let mut iv: Vec<u8> = [0;16].to_vec();
	let block_size = 16;
	let block_count = s.len() / block_size;
	let mut decrypted_all: Vec<u8> = Vec::new();
	println!("Decrypting {} blocks from input size {}", block_count, s.len());
	for i in 0..block_count {
		let block = s[(block_size * i)..((block_size * i) + block_size)].to_vec();
		let mut decrypted: Vec<u8> = Vec::new();
		let result = decrypt_block(&key, &block);
		for i in 0..16 {
			decrypted.push(result[i] ^ iv[i]);
		}
		decrypted_all.extend(decrypted);
		iv = block;
	}
	println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_all));
	println!("Encrypting {} blocks from input size {}", block_count, s.len());
	let mut encrypted_all: Vec<u8> = Vec::new();
	iv = [0;16].to_vec();
	for i in 0..block_count {
		let block = decrypted_all[(block_size * i)..((block_size * i) + block_size)].to_vec();
		let mut xord: Vec<u8> = Vec::new();
		for i in 0..16 {
			xord.push(block[i] ^ iv[i]);
		}
		let encrypted = encrypt_block(&key, &xord)[0..16].to_vec();
		encrypted_all.extend(&encrypted);
		iv = encrypted;
	}
	println!("Encrypted: {}", encrypted_all.to_base64(STANDARD));
}
