extern crate rustc_serialize as serialize;

use serialize::hex::ToHex;

use std::env;
use std::process;

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

fn main() {
    let args: Vec<String> = env::args().collect();

	if args.len() < 3 {
		println!("No argument provided - run as ./chal1 $hex_string $pad_size");
		process::exit(1);
	}
	let ref hex: String = args[1].as_bytes().to_hex();
    println!("Hex Input: {}", hex);
	let count = match args[2].parse::<u8>() {
	  Ok(n) => n,
	  Err(e) => {
		println!("Failed to pass pad size argument: {}",e);
		process::exit(1);
	  },
	};
	let padded = pad(args[1].as_bytes(), count);
	println!("Hex output: {}", padded.to_hex());
}