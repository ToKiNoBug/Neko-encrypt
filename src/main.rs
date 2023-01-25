use clap::Parser;
use encryp::{encryp_file, encryp_option};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Files to encrypt
    files: Vec<String>,

    /// Whether to keep
    #[arg(short, long, default_value_t = false)]
    keep: bool,

    /// Whether to cover existing file
    #[arg(long, default_value_t = true)]
    cover_existing_file: bool,

    #[arg(long, default_value_t = 65536)]
    buffer_size: isize,
}

fn main() {
    let args = Args::parse();

    println!("args = {:?}", args);

    let opt = encryp_option {
        keep: args.keep,
        cover_existing_file: args.cover_existing_file,
    };

    for i in 0..args.files.len() {
        let src_filename: &String = &args.files[i];
        let dst_filename: String = src_filename.clone() + ".rua";

        if !encryp_file(&src_filename, &dst_filename, &opt) {
            eprintln!(
                "Failed to encryp file {} to {}.",
                src_filename, dst_filename
            );
            return;
        }
    }

    let mut tent = encryp::tent_chaos::new(0);

    let mut vector: Vec<u64> = Vec::new();
    vector.resize(1024, 0);

    tent.iterate_vec(1024, &mut vector).unwrap();

    println!("The vector is {:?}", vector);

    return;
}
