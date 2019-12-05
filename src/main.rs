use gimli::{gimli_aead_decrypt, gimli_aead_encrypt, gimli_hash};
use structopt::StructOpt;
use clap::arg_enum;
use std::path::PathBuf;
use std::fs::File;
use std::io::prelude::*;

arg_enum! {
    #[derive(Debug)]
    enum GimliMode {
        Hash,
        Encrypt,
        Decrypt,
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Gimli-rs",
    about = "An implementation of the gimli cipher with hashing and AEAD functionality"
)]


struct Opt {
    /// Input.
    #[structopt(
        short = "i",
        long = "input"
        )]
    input: String,

    /// Enable to parse input as a file path
    #[structopt(
        short = "f",
        long = "is_file"
        )]
    is_file: bool,

    /// Mode of operation.
    #[structopt(
        short = "m",
        long = "mode",
        possible_values = &GimliMode::variants(),
        default_value = "hash",
        case_insensitive = true
        )]
    mode: GimliMode,

    /// Output. Defaults to std out.
    #[structopt(
        short = "o",
        long = "out",
        parse(from_os_str),
        )]
    output: Option<PathBuf>,

    /// Crypto Key.
    #[structopt(
        short = "k",
        long = "key",
        required_if("mode", "encrypt"),
        required_if("mode", "decrypt"),
        default_value = "",
        )]
    key: String,

        /// Associated data.
    #[structopt(
        short = "a",
        long = "associated_data",
        required_if("mode", "encrypt"),
        required_if("mode", "decrypt"),
        default_value = "",
        )]
    ad: String,

    /// Hash length. Required for Hash mode.
    #[structopt(
        short = "l",
        long = "length",
        default_value = "32",
        requires_if("mode", "hash"),
        )]
    out_length: u64,
}




fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);

    match opt.mode {
        GimliMode::Hash => {
            match opt.is_file {
                true => {
                    let contents = open_input_file(opt.input);
                    let result = gimli_hash(
                    &contents,
                    contents.len() as u64,
                    opt.out_length);
                    match opt.output {
                        Some(file_path) => {
                            let mut file = File::create(file_path).expect("Failed to open output file");
                            file.write_all(&result).expect("Error writing to output file");
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    }
                }
                false => {
                    let result = gimli_hash(
                    opt.input.as_bytes(),
                    opt.input.as_bytes().len() as u64,
                    opt.out_length);
                    match opt.output {
                        Some(file_path) => {
                            let mut file = File::create(file_path).expect("Failed to open output file");
                            file.write_all(&result).expect("Error writing to output file");
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    } 
                }
            }
        },
        GimliMode::Encrypt => {
            let key_hash = gimli_hash(opt.key.as_bytes(), opt.key.as_bytes().len() as u64, 32);
            let mut key_array = [0; 32];
            key_array.copy_from_slice(&key_hash);
            match opt.is_file {
                true => {
                    let contents = open_input_file(opt.input);
                    let result = gimli_aead_encrypt(
                    &contents,
                    opt.ad.as_bytes(),
                    &[0; 16],
                    &key_array);
                    match opt.output {
                        Some(file_path) => {
                            let mut file = File::create(file_path).expect("Failed to open output file");
                            file.write_all(&result).expect("Error writing to output file");
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    }
                }
                false => {
                    let result = gimli_aead_encrypt(
                    opt.input.as_bytes(),
                    opt.ad.as_bytes(),
                    &[0; 16],
                    &key_array);
                    match opt.output {
                        Some(file_path) => {
                            let mut file = File::create(file_path).expect("Failed to open output file");
                            file.write_all(&result).expect("Error writing to output file");
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    } 
                }
            }

        },
        GimliMode::Decrypt => {
            let key_hash = gimli_hash(opt.key.as_bytes(), opt.key.as_bytes().len() as u64, 32);
            let mut key_array = [0; 32];
            key_array.copy_from_slice(&key_hash);
            match opt.is_file {
                true => {
                    let contents = open_input_file(opt.input);
                    let result = gimli_aead_decrypt(
                    &contents,
                    opt.ad.as_bytes(),
                    &[0; 16],
                    &key_array).expect("Error decypting");
                    match opt.output {
                        Some(file_path) => {
                            let mut file = File::create(file_path).expect("Failed to open output file");
                            file.write_all(&result).expect("Error writing to output file");
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    }
                }
                false => {
                    let result = gimli_aead_decrypt(
                    opt.input.as_bytes(),
                    opt.ad.as_bytes(),
                    &[0; 16],
                    &key_array).expect("Error decypting");
                    match opt.output {
                        Some(file_path) => {
                            let mut file = File::create(file_path).expect("Failed to open output file");
                            file.write_all(&result).expect("Error writing to output file");
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    } 
                }
            }

        },

    }

    fn open_input_file(path: String) -> Vec<u8>{
        let mut input_file = File::open(path).expect("Error opening input file.");
        let mut contents = vec![];
        input_file.read_to_end(&mut contents).expect("Error reading input file.");
        return contents
    }


    // println!("Input bytes: {:x?}", opt.input.as_bytes());

    // println!("result: {:x?}", result);
    // println!("result length: {:?}", result.len());
    // println!("In c hexstring format");
    // for byte in result.iter(){
    //     print!("{:02x?}", byte);
    // }
    // println!("");
    // let plaintext = opt.input;
    // let plaintext = plaintext.as_bytes();
    // println!("Testing encryption");
    // print!("Plaintext: \n");
    // for byte in plaintext.iter() {
    //     print!("{:02x?}", byte);
    // }
    // println!("");
    // println!("Plaintext len: {}", plaintext.len());
    // let ad = vec![0; 16];
    // let nonce = [0; 16];
    // let key = [0; 32];
    // println!("Encryption:");
    // let e_data = gimli_aead_encrypt(plaintext, &ad, &nonce, &key);
    // for byte in e_data.iter() {
    //     print!("{:02x?}", byte);
    // }
    // println!("");
    // println!("Ciphertext len: {}", e_data.len());
    // println!("Decryption:");
    // let d_data = gimli_aead_decrypt(&e_data, &ad, &nonce, &key);
    // match d_data {
    //     Ok(v) => {
    //         for byte in v.iter() {
    //             print!("{:02x?}", byte);
    //         }
    //         println!("");
    //         println!("Decryption len: {:?}", v.len());
    //     }
    //     Err(e) => {
    //         println!("Decrypt errored with {:?}", e);
    //     }
    // }
}
