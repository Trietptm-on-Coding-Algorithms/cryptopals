extern crate rustc_serialize as serialize;

use serialize::base64::FromBase64;
use serialize::hex::ToHex;
use std::collections::HashMap;

use std::env;
use std::process;
use std::str;

use std::fs::File;
use std::io::Read;

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

fn hamming_distance(one: &[u8], two: &[u8]) -> u8 {
	let mut distance: u8 = 0;
	for i in 0..one.len(){
		for j in 0..8{
			let bit_one = (one[i] >> j) & 1;
			let bit_two = (two[i] >> j) & 1;
			if bit_one != bit_two {
				distance += 1;
			}
		}
	}
	distance
}

fn break_one_byte_xor(target: Vec<u8>) -> u8 {
	let mut high_score = 0.0;
	let mut xor_key = 0;
	for j in 0..255{
		let mut out: Vec<u8> = Vec::new();
		for i in &target {
			out.push(i ^ j); 
		}
		let s = match str::from_utf8(out.as_slice()) {
			Ok(v) => v,
			Err(e) => continue,
		};
		let score = score_string(s);

		if score > high_score {
			high_score = score;
			xor_key = j;
		}
	}
	xor_key
}

fn break_multi_byte_xor(s: &Vec<u8>, window_size: usize) -> Vec<u8> {
	let mut blocks: Vec<Vec<u8>> = Vec::new();
	let block_count = s.len() / window_size;
	println!("Block count: {}", block_count);
	for i in 0..block_count {
		let mut row: Vec<u8> = Vec::new();
		for j in 0..window_size {
			let index = (i * window_size) + j;
			row.push(s[index]);
		}
		blocks.push(row);
	}
	println!("Created {} groups of {} byte blocks", blocks.len(), window_size);
	let mut transposed_blocks: Vec<Vec<u8>> = Vec::new();
	for i in 0..window_size {
		let mut transposed_row: Vec<u8> = Vec::new();
		for row in &blocks {
			transposed_row.push(row[i]);
		}
		transposed_blocks.push(transposed_row);
	}
	println!("Transposed blocks into {} xor ciphers", transposed_blocks.len());
	let mut xor_key: Vec<u8> = Vec::new();
	for cipher in transposed_blocks {
		let byte_xor_key = break_one_byte_xor(cipher);
		xor_key.push(byte_xor_key);
	}
	println!("Final key: {}", xor_key.to_hex());
	xor_key
}

fn repeat_xor(s: &Vec<u8>, key: Vec<u8>) -> Vec<u8> {
	let mut out: Vec<u8> = Vec::new();
	let key_len = key.len();
	for i in 0..s.len() {
		out.push(s[i] ^ key[i % key_len]);
	}
	out
}

fn main() {
    let args: Vec<String> = env::args().collect();

	if args.len() < 2 {
		println!("No argument provided - run as ./chal6 $input_file");
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
	let mut distances = HashMap::new();
	for window in 2..40 {
		let distance_one = hamming_distance(&s[0..window], &s[window..window*2]);
		let distance_two = hamming_distance(&s[window*2..window*3], &s[window*3..window*4]);
		let avg_distance = (distance_one + distance_two) as f64/ ( 2* window) as f64;
		distances.insert(window, avg_distance);
	}
	let mut final_text_score = 0.0;
	for _ in 0..6 {
		let mut lowest_distance = 8.0;
		let mut current_window = 0;
		for (window, distance) in &distances {
			if *distance < lowest_distance {
				lowest_distance = *distance;
				current_window = *window;
			}
		}
		println!("Block size: {} distance: {}", current_window, lowest_distance);
		distances.remove(&current_window);
		let xor_key = break_multi_byte_xor(&s, current_window);
		let out = repeat_xor(&s, xor_key);
		let s = match str::from_utf8(out.as_slice()) {
			Ok(v) => v,
			Err(e) => continue,
		};
		let score = score_string(s);
		if score > final_text_score {
			final_text_score = score;
			println!("Decoded message: {}", String::from_utf8_lossy(&out));
		}
	}
	
}
