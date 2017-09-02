extern crate rustc_serialize as serialize;

use serialize::hex::ToHex;

use std::env;
use std::process;
use std::str;

use std::fs::File;
use std::io::Read;

fn repeat_xor(s: String, key: &String) -> Vec<u8> {
	println!("{}",s);
	let mut out: Vec<u8> = Vec::new();
	let s_raw = s.as_bytes();
	let key_raw = key.as_bytes();
	let key_len = key.len();
	for i in 0..s_raw.len() {
		out.push(s_raw[i] ^ key_raw[i % key_len]);
	}
	out
}

fn main() {
	
	
    let args: Vec<String> = env::args().collect();

	if args.len() < 3 {
		println!("No argument provided - run as ./chal5 $key $input_file");
		process::exit(1);
	}
	let mut f = match File::open(&args[2]) {
		Ok(file) => file,
		Err(e) => {
			println!("Failed to open file: {}", e);
			process::exit(1);
		}
	};
	let mut contents = String::new();
    f.read_to_string(&mut contents).expect("Failed to read input file.");
	let mut out: Vec<u8> = Vec::new();
	out.extend(repeat_xor(contents, &args[1]));

	println!("{}", out.to_hex());
}