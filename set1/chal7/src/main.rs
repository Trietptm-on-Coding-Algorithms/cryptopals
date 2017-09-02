extern crate rustc_serialize as serialize;
extern crate openssl as openssl;

use serialize::base64::FromBase64;
use serialize::hex::ToHex;
use serialize::hex::FromHex;

use std::env;
use std::process;
use std::str;

use std::fs::File;
use std::io::Read;

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
	let key = args[2].as_bytes();
	let cipher = openssl::symm::Cipher::aes_128_ecb();
	let result = match openssl::symm::decrypt(cipher, &key, None, &s) {
		Ok(data) => data,
		Err(e) => {
			println!("Failed to decrypt file: {}", e);
			process::exit(1);
		}
	};
	println!("Decrypted: {}", String::from_utf8_lossy(&result));
}
