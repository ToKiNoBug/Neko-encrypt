use std::fs;
//use std::io;
use std::io::prelude::*;

#[allow(non_camel_case_types)]
pub struct encryp_option {
    pub keep: bool,
    pub cover_existing_file: bool,
}

pub fn encryp_file(src_name: &String, dst_name: &String, opt: &encryp_option) -> bool {
    if src_name == dst_name {
        eprintln!(
            "Error : source filename ({}) is equal to destination({})",
            src_name, dst_name
        );
        return false;
    }

    {
        let file = fs::File::open(dst_name);
        if file.is_ok() && !opt.cover_existing_file {
            eprintln!("Error : destination file {} already exists.", dst_name);
            return false;
        }
    }
    let ifile = fs::File::open(src_name);
    if !ifile.is_ok() {
        eprintln!("Error : failed to open source file {}", src_name);
        return false;
    }

    let ofile = fs::File::create(dst_name);
    if !ofile.is_ok() {
        eprintln!("Error : failed to open/create dest file {}", dst_name);
        return false;
    }

    let buffer_size: usize = 65536;

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(buffer_size, 0xFF);

    loop {
        //loop {
        let read_bytes = ifile.as_ref().unwrap().read(&mut buffer).unwrap();

        //println!("{read_bytes} bytes read");

        ofile
            .as_ref()
            .unwrap()
            .write(&buffer[0..read_bytes])
            .unwrap();
        //}
        //println!("{wrote_bytes} bytes wrote");

        if read_bytes < buffer_size {
            break;
        }
    }

    return true;
}
