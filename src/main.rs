use structopt::StructOpt;
use gimli::{gimli_hash, gimli_aead_encrypt, gimli_aead_decrypt};

#[derive(Debug, StructOpt)]
#[structopt(name = "Gimli-rs", about = "An implementation of the gimli cipher in hash mode.")]
struct Opt {
    /// Input string
    #[structopt(short)]
    input: String,

    /// Hash length
    #[structopt(short)]
    out_length: u64,
}

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    println!("{:?}", opt.input);
    // println!("Input bytes: {:x?}", opt.input.as_bytes());
    // let result = gimli_hash(
    //     opt.input.as_bytes(),
    //     opt.input.as_bytes().len() as u64,
    //     opt.out_length);
    // println!("result: {:x?}", result);
    // println!("result length: {:?}", result.len());
    // println!("In c hexstring format");
    // for byte in result.iter(){
    //     print!("{:02x?}", byte);
    // }
    // println!("");
    let plaintext = opt.input.as_bytes();
    println!("Testing encryption");
    print!("Plaintext: \n");
    for byte in plaintext.iter(){
        print!("{:02x?}", byte);
    }
    println!("");
    println!("Plaintext len: {}", plaintext.len());
    let ad = vec![0; 16];
    let nonce = [0; 16];
    let key = [0; 32];
    println!("Encryption:");
    let e_data = gimli_aead_encrypt(plaintext, &ad, &nonce, &key);
    for byte in e_data.iter(){
        print!("{:02x?}", byte);
    }
    println!("");
    println!("Ciphertext len: {}", e_data.len());
    println!("Decryption:");
    let d_data = gimli_aead_decrypt(&e_data, &ad, &nonce, &key);
    match d_data {
        Ok(v) => {
            for byte in v.iter(){
                print!("{:02x?}", byte);
            }
            println!("");
            println!("Decryption len: {:?}", v.len());
        }
        Err(e) => {println!("Decrypt errored with {:?}", e);}
    }


}
