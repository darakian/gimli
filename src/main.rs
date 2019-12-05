use gimli::{gimli_aead_decrypt, gimli_aead_encrypt, gimli_hash};
use structopt::StructOpt;
use clap::arg_enum;
use std::path::PathBuf;

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
    about = "An implementation of the gimli cipher in hash mode."
)]


struct Opt {
    /// Input mode.
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

    /// Output file. Required for Encrypt/Decrypt
    #[structopt(
        short = "o",
        long = "out",
        requires_ifs(&[("mode", "encrypt"), ("mode", "decrypt")]),
        required_ifs(&[("mode", "encrypt"), ("mode", "decrypt")]),
        parse(from_os_str),
        )]
    output: Option<PathBuf>,

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
    println!("{:?}", opt.input);

    match opt.mode {
        GimliMode::Hash => {
            let result = gimli_hash(
        opt.input.as_bytes(),
        opt.input.as_bytes().len() as u64,
        opt.out_length);
        for byte in result.iter(){
        print!("{:02x?}", byte);
            }
        },
        GimliMode::Encrypt => {},
        GimliMode::Decrypt => {},

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


