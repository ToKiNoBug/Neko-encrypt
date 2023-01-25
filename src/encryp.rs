use std::fs;
//use std::io;
use std::io::prelude::*;

#[allow(non_camel_case_types)]
pub struct encryp_option {
    pub keep: bool,
    pub cover_existing_file: bool,
}

#[allow(non_camel_case_types)]
struct file_streams_pair {
    ifile: fs::File,
    ofile: fs::File,
}

fn create_file_stream(
    src_name: &String,
    dst_name: &String,
    opt: &encryp_option,
) -> Result<file_streams_pair, String> {
    if src_name == dst_name {
        return Err(String::from(
            "Error : source filename is equal to destination",
        ));
    }

    {
        let file = fs::File::open(dst_name);
        if file.is_ok() && !opt.cover_existing_file {
            return Err(String::from("Error : destination file already exists."));
        }
    }
    let ifile = fs::File::open(src_name);
    if !ifile.is_ok() {
        return Err(String::from("Error : failed to open source file."));
    }

    //let mut ifile = ifile.as_ref().unwrap();

    let ofile = fs::File::create(dst_name);
    if !ofile.is_ok() {
        return Err(String::from("Error : failed to open/create dest file {}"));
    }

    //let mut ofile = ofile.as_ref().unwrap();

    return Ok(file_streams_pair {
        ifile: (ifile.unwrap()),
        ofile: (ofile.unwrap()),
    });
}

pub fn encryp_file(src_name: &String, dst_name: &String, opt: &encryp_option) -> bool {
    let streams = create_file_stream(src_name, dst_name, opt);

    if streams.is_err() {
        return false;
    }

    let mut ifile = &streams.as_ref().unwrap().ifile;
    let mut ofile = &streams.as_ref().unwrap().ofile;

    let buffer_size: usize = 65536;

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(buffer_size, 0xFF);

    loop {
        //loop {
        let read_bytes = ifile.read(&mut buffer).unwrap();

        //println!("{read_bytes} bytes read");

        ofile.write(&buffer[0..read_bytes]).unwrap();
        //}
        //println!("{wrote_bytes} bytes wrote");

        if read_bytes < buffer_size {
            break;
        }
    }

    return true;
}

use std::num::Wrapping;

#[allow(non_camel_case_types)]
pub struct tent_chaos {
    value: Wrapping<u64>,
    iterate_times: u64,
}

impl tent_chaos {
    pub fn new(value: u64) -> tent_chaos {
        let ret = tent_chaos {
            value: Wrapping(value),
            iterate_times: 0,
        };

        return ret;
    }

    pub fn iterate(&mut self) -> u64 {
        let k = Wrapping(self.iterate_times << 2);
        let g = self.value + k;

        let seperator = Wrapping(1_u64 << 63);

        if g < seperator {
            self.value = g << 1 + 1;
        } else {
            self.value = (Wrapping(!(0_u64)) - g) << 1;
        }

        self.iterate_times += 1;

        return self.value.0;
    }

    fn iterate_many_private(&mut self, times: u64, data: *mut u64, do_encrypt: bool) {
        let mut k = Wrapping(self.iterate_times << 2);
        let mut x = self.value;

        let seperator = Wrapping(1_u64 << 63);
        let mut it: u64 = 0;
        loop {
            if it >= times {
                break;
            }
            let g = x + k;
            if g < seperator {
                x = g << 1 + 1;
            } else {
                x = (Wrapping(!(0_u64)) - g) << 1;
            }

            if !data.is_null() {
                unsafe {
                    if do_encrypt {
                        *(data.add(it as usize)) = x.0;
                    } else {
                        *(data.add(it as usize)) ^= x.0;
                    }
                }
            }

            it += 1;
            k += 4;
        }

        self.value = x;
        self.iterate_times += times;
    }

    pub fn iterate_vec(&mut self, times: u64, vec: &mut [u64]) -> Result<(), String> {
        if vec.len() != times as usize {
            return Err(String::from("Size mismatch."));
        }

        self.iterate_many_private(times, vec.as_mut_ptr(), false);

        return Ok(());
    }

    pub fn encrypt(&mut self, vec: &mut [u8]) -> Result<(), String> {
        if vec.len() % 8 != 0 {
            return Err(String::from("Length of u8 array should be multiples of 8."));
        }

        self.iterate_many_private(vec.len() as u64 / 8, vec.as_mut_ptr() as *mut u64, true);

        return Ok(());
    }

    pub fn iterate_no_ret(&mut self, times: u64) {
        let mut i = 0u64;
        loop {
            if i >= times {
                break;
            }
            self.iterate();
            i += 1;
        }
    }
}

use checksums;

pub fn test_checksum(filename: &String) {
    let mut ifile = fs::File::open(filename).unwrap();

    let mut buffer: [u8; 65536] = [0; 65536];

    let buffer_bytes = buffer.len();

    let mut algo = checksums::Algorithm::SHA3512;

    let opt = checksums::hash_reader(&mut ifile, algo);

    loop {
        let bytes_read = ifile.read(buffer.as_mut_slice()).unwrap();

        if bytes_read < buffer_bytes {
            break;
        }
    }
}
