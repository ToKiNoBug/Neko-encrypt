use clap::Parser;
use encryp::{decrypt_file, encryp_file, encryp_option, test_checksum};
use std::fs;
use std::path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Files to encrypt
    files: Vec<String>,

    /// Whether to keep
    #[arg(short, long, default_value_t = false)]
    keep: bool,

    /// Whether to cover existing file
    #[arg(long, default_value_t = false)]
    cover_existing_file: bool,

    #[arg(long, default_value_t = 65536)]
    buffer_size: usize,

    #[arg(short,long, default_value_t = String::from(""))]
    password: String,

    #[arg(short, long, default_value_t = false)]
    deencrypt: bool,
}

fn main() {
    let args = Args::parse();

    //println!("args = {:?}", args);

    let opt = encryp_option::create(
        args.keep,
        args.cover_existing_file,
        &args.password,
        args.buffer_size,
    );

    //println!("opt = {:?}", opt);

    for i in 0..args.files.len() {
        let src_filename: &String = &args.files[i];

        if !args.deencrypt {
            let dst_filename: String = src_filename.clone() + encryp::suffix;

            if !encryp_file(&src_filename, &dst_filename, &opt) {
                eprintln!(
                    "Failed to encryp file {} to {}.",
                    src_filename, dst_filename
                );
                return;
            }
        } else {
            ////////////////////////
            let mut dst_name: String = String::new();
            if !decrypt_file(&src_filename, &opt, &mut dst_name) {
                if path::Path::new(&dst_name).exists() {
                    fs::remove_file(dst_name).expect("Failed to remove file.");
                }

                return;
            }
        }

        if !opt.keep {
            let ret = std::fs::remove_file(src_filename);
            if ret.is_err() {
                eprintln!(
                    "Failed to remove file {:?}, detail : {:?}",
                    src_filename,
                    ret.unwrap_err()
                );

                return;
            }
        }
        if false {
            test_checksum(&src_filename);
        }
    }

    /*/
        let mut tent = encryp::tent_chaos::new(0);

        let mut vector: Vec<u64> = Vec::new();
        vector.resize(1024, 0);

        tent.iterate_vec(1024, &mut vector).unwrap();

        //println!("The vector is {:?}", vector);

    */
    return;
}
