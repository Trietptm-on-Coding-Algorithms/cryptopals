extern crate rustc_serialize as serialize;

use serialize::hex::FromHex;
use serialize::hex::ToHex;
use std::collections::HashMap;

use std::env;
use std::process;
use std::str;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

fn main() {
    let args: Vec<String> = env::args().collect();

	if args.len() < 2 {
		println!("No argument provided - run as ./chal4 $input_file");
		process::exit(1);
	}
	let f = match File::open(&args[1]) {
		Ok(file) => file,
		Err(e) => {
			println!("Failed to open file: {}", e);
			process::exit(1);
		}
	};
	let block_size = 16;
	let file = BufReader::new(&f);
	println!("Block size: {}", block_size);
	for line in file.lines() {
		let data = line.unwrap().from_hex().unwrap();
		let block_count = data.len() / block_size;
		let mut counts = HashMap::new();
		for i in 0..block_count {
			let entry: Vec<u8> = data[i*block_size..(i*block_size) + block_size].to_vec();
			let count = counts.entry(entry).or_insert(0);
			*count += 1;
		}
		for (key, count) in counts {
			if count > 1 {
				println!("Potentially ECB encrypted entry: {}, Follow block found {} times: {}", data.to_hex(), count, key.to_hex());
				continue;
			}
		}
	}
}
