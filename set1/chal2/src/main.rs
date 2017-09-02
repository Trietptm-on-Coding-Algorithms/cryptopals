extern crate rustc_serialize as serialize;

use serialize::hex::{FromHex, ToHex};

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

	if args.len() < 3 {
		println!("No argument provided - run as ./chal2 $hex_string $hex_string");
		process::exit(1);
	}
	
	if args[1].len() != args[2].len() {
		println!("Arguments should be equal length hex strings for fixed key xor!");
		process::exit(1);
	}
	
	let ref a: String = args[1];
	let raw_a = a.from_hex().unwrap();
	let ref b: String = args[2];
	let raw_b = b.from_hex().unwrap();
	let mut out: Vec<u8> = Vec::new();
	for i in 0..raw_a.len() {
		out.push(raw_a[i] ^ raw_b[i]); 
	}
	println!("XOR'd data: {}", out.to_hex());
}