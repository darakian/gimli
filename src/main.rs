use gimli_rs::{gimli_aead_decrypt, gimli_aead_encrypt, gimli_hash};
use structopt::StructOpt;
use structopt::clap::arg_enum;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use rand::prelude::*;

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
        )]
    output: Option<String>,

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
                    let f = File::open(opt.input).expect("Error opening file for hashing.");
                    let file_len = f.metadata().expect("Error reading input file length").len();
                    let reader = BufReader::new(f);
                    let result = gimli_hash(
                    reader.bytes(),
                    file_len,
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
                    let input_len = opt.input.as_bytes().len() as u64;
                    let result = gimli_hash(
                    opt.input.into_bytes().into_iter().map(|x| Ok(x)),
                    input_len,
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
            let mut rng = rand::thread_rng();
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            let key_len = opt.key.as_bytes().len() as u64;
            let key_hash = gimli_hash(
                opt.key.into_bytes().into_iter().map(|x| Ok(x)),
                key_len,
                32);
            let mut key_array = [0; 32];
            key_array.copy_from_slice(&key_hash);
            match opt.is_file {
                true => {
                    let contents = open_input_file(opt.input);
                    let contents_len = contents.len();
                    let result = gimli_aead_encrypt(
                    contents.into_iter().map(|x| Ok(x)),
                    contents_len,
                    opt.ad.as_bytes(),
                    &nonce,
                    &key_array);
                    match opt.output {
                        Some(file_path) => {
                            write_encrypted_file(file_path, &nonce, result);
                        },
                        None => {
                                for byte in result.iter(){
                                    print!("{:02x?}", byte);
                                }
                        },
                    }
                }
                false => {
                    let input_len = opt.input.as_bytes().len();
                    let result = gimli_aead_encrypt(
                    opt.input.into_bytes().into_iter().map(|x| Ok(x)),
                    input_len,
                    opt.ad.as_bytes(),
                    &nonce,
                    &key_array);
                    match opt.output {
                        Some(file_path) => {
                            write_encrypted_file(file_path, &nonce, result);
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
            let key_len = opt.key.as_bytes().len() as u64;
            let key_hash = gimli_hash(
                opt.key.into_bytes().into_iter().map(|x| Ok(x)),
                key_len,
                32);
            let mut key_array = [0; 32];
            key_array.copy_from_slice(&key_hash);
            match opt.is_file {
                true => {
                    let mut contents = open_input_file(opt.input);
                    let contents_len = contents.len();
                    let mut nonce = [0; 16]; 
                    nonce.copy_from_slice(&contents[..16]);
                    contents = contents[16..].to_vec();
                    let result = gimli_aead_decrypt(
                    contents.into_iter().map(|x| Ok(x)),
                    contents_len,
                    opt.ad.as_bytes(),
                    &nonce,
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
                    let mut input_bytes = opt.input.into_bytes();
                    let mut nonce = [0; 16];
                    nonce.copy_from_slice(&input_bytes[..16]);
                    let input_len = input_bytes.len();
                    input_bytes = input_bytes[16..].to_vec();
                    let result = gimli_aead_decrypt(
                    input_bytes.into_iter().map(|x| Ok(x)),
                    input_len,
                    opt.ad.as_bytes(),
                    &nonce,
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

    fn write_encrypted_file(path: String, nonce: &[u8; 16], ciphertext: Vec<u8>) -> (){
        let mut file = File::create(path).expect("Failed to open output file");
        file.write_all(nonce).expect("Error writing to output file");
        file.write_all(&ciphertext).expect("Error writing to output file");
    }
}
