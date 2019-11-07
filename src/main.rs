use structopt::StructOpt;
use gimli::Gimli_hash;

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
    println!("Input bytes: {:x?}", opt.input.as_bytes());
    let result = Gimli_hash(
        opt.input.as_bytes(),
        opt.input.as_bytes().len() as u64,
        opt.out_length);
    println!("result: {:x?}", result);
    println!("result length: {:?}", result.len());
}