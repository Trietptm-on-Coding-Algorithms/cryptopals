//I was very lazy/hungover while solving this one, read at the risk of your own sanity.
extern crate rustc_serialize as serialize;
extern crate openssl;
extern crate rand;

use serialize::hex::ToHex;
use std::process;
use std::str;

fn pad(input: &[u8], pad_size: u8) -> Vec<u8> {
	let mut out: Vec<u8> = Vec::new();
	let rem = input.len() as u8 % pad_size;
	let pad_val = pad_size - rem;
	out.extend(input);
	if rem != 0 {
		for _ in 0..pad_val {
			out.push(pad_val);
		}
	}
	out
}


struct User {
	email: String,
	uid: u8,
	role: String
}

fn random_aes_key() -> Vec<u8> {
	let mut out: Vec<u8> = Vec::new();
	for _ in 0..16 {
		let byte = rand::random::<u8>();
		out.push(byte);
	}
	out
}

fn decrypt_block(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
	let cipher = openssl::symm::Cipher::aes_128_ecb();
	let result = match openssl::symm::decrypt(cipher, &key, None, &data) {
		Ok(data) => data,
		Err(e) => {
			println!("Failed to decrypt data: {}", e);
			process::exit(1);
		}
	};
	result
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

fn decrypt_and_parse(key: &Vec<u8>, encrypted_cookie: &Vec<u8>) -> User {
	let cookie = decrypt_block(key, encrypted_cookie);
	let to_parse = String::from_utf8_lossy(&cookie);
	println!("Decrypted: {}", to_parse);
	let mut email = "invalid";
	let mut uid = 0;
	let mut role = "user";
	for field in to_parse.split("&") {
		let val_start = field.find("=").unwrap() + 1;
		let value = &field[val_start..field.len()];
		println!("Data: {}, {}", field, value);
		if field.starts_with("email") {
			email = value;
		} else if field.starts_with("uid") {
			uid = value.parse::<u8>().unwrap();
		} else if field.starts_with("role") {
			role = value;
		} else {
			println!("Invalid field found!");
		}
	}
	let user = User {
		email: email.to_string(),
		uid: uid,
		role: role.to_string()
	};
	user
}

fn profile_for(key: &Vec<u8>, email: &Vec<u8>) -> Vec<u8> {
	let mut filtered_email = email.to_vec();
	filtered_email.retain(|e| *e != 61);
	filtered_email.retain(|e| *e != 38);
	let uid = rand::random::<u8>();
	let mut to_encrypt = "email=".as_bytes().to_vec();
	to_encrypt.extend(filtered_email);
	to_encrypt.extend("&uid=".as_bytes());
	to_encrypt.extend(uid.to_string().as_bytes());
	to_encrypt.extend("&role=user".as_bytes());
	encrypt_block(key, &to_encrypt)
}

fn main() {
    let key = random_aes_key();
	println!("Global key: {}", key.to_hex());
	let block_size = 16;
	let test = profile_for(&key, &"test".as_bytes().to_vec());
	let start_len = test.len();
	let user_input = pad("user".as_bytes(), block_size);
	let mut start_pad = Vec::new();
	for _ in 0..block_size - 6 {
		start_pad.push(0x41);
	}
	start_pad.extend(user_input);
	let user_test = profile_for(&key, &start_pad);
	let user_encrypted = &user_test[block_size as usize..(block_size*2) as usize];
	println!("String 'user' encrypted with padding: {}", user_encrypted.to_hex());
	let mut to_tamper: Vec<u8> = Vec::new();
	let mut buf = Vec::new();
	for _ in 0..block_size {
		for _ in 0..5 {
			let submit = buf.to_vec();
			let test = profile_for(&key, &submit);
			if test.len() > start_len {
				let role = &test[start_len..start_len + block_size as usize];
				if user_encrypted == role {
					to_tamper = test.to_vec();
					break;
				}
			}
		}
		if to_tamper.len() != 0 {
			break;
		}
		buf.push(0x41);
	}
	println!("Cookie tamper target: {}", to_tamper.to_hex());
	let admin_input = pad("admin".as_bytes(), block_size);
	let mut admin_pad = Vec::new();
	for _ in 0..block_size - 6 {
		admin_pad.push(0x41);
	}
	admin_pad.extend(admin_input);
	let admin_test = profile_for(&key, &admin_pad);
	let admin_encrypted = &admin_test[block_size as usize..(block_size*2) as usize];
	println!("String 'admin' encrypted with padding: {}", admin_encrypted.to_hex());	
	for i in 0..block_size {
		to_tamper[start_len + i as usize] = admin_encrypted[i as usize];
	}
	println!("Modified cookie: {}", to_tamper.to_hex());
	let user = decrypt_and_parse(&key, &to_tamper);
	if user.role == "admin" {
		println!("Win!");
	} else {
		println!("standard user? {}", user.role);
	}
}
