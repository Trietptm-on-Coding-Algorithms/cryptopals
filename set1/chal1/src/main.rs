extern crate rustc_serialize as serialize;

use serialize::base64::{self, ToBase64};
use serialize::hex::FromHex;

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

	if args.len() < 2 {
		println!("No argument provided - run as ./hex_to_b64 $hex_string");
		process::exit(1);
	}
	let ref hex: String = args[1];
    println!("Hex Input: {}.", hex);
	let raw_bytes = hex.from_hex().unwrap();
	let b64 = raw_bytes.to_base64(base64::STANDARD);
	println!("Base64 Output: {}.", b64);
}