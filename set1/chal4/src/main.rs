extern crate rustc_serialize as serialize;

use serialize::hex::FromHex;
use std::collections::HashMap;

use std::env;
use std::process;
use std::str;

use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

fn score_string(s: &str) -> f64 {
	let mut eng_freq = HashMap::new();
	eng_freq.insert(" ", 19.1);
	eng_freq.insert("e",10.41);
	eng_freq.insert("t",7.29);
	eng_freq.insert("a",6.52);
	eng_freq.insert("o",5.96);
	eng_freq.insert("i",5.58);
	eng_freq.insert("n",5.64);
	eng_freq.insert("s",5.16);
	eng_freq.insert("h",4.93);
	eng_freq.insert("r",4.98);
	eng_freq.insert("d",3.50);
	eng_freq.insert("l",3.31);
	eng_freq.insert("u",2.25);
	eng_freq.insert("c",2.17);
	eng_freq.insert("m",2.02);
	eng_freq.insert("f",1.98);
	eng_freq.insert("w",1.71);
	eng_freq.insert("g",1.59);
	eng_freq.insert("y",1.46);
	eng_freq.insert("p",1.38);
	
	let mut score = 0.0;
	for char in s.chars() {
		if char.is_control() {
			continue;
		}
		let char_lower = char.to_lowercase().to_string();
		let freq = match eng_freq.get(char_lower.as_str()){
			Some(v) => *v,
			None => continue,
		};
		score += freq;
	}
	score
}

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
	let file = BufReader::new(&f);
	for line in file.lines() {
		let raw_in = line.unwrap().from_hex().unwrap();
		for j in 0..255{
			let mut out: Vec<u8> = Vec::new();
			for i in 0..raw_in.len() {
				out.push(raw_in[i] ^ j); 
			}
			let s = match str::from_utf8(out.as_slice()) {
				Ok(v) => v,
				Err(e) => continue,
			};
			let score = score_string(s);

			if score > 200.0 {
				println!("Score: {} Value: {}", score, s);
			}
		}
	}
}