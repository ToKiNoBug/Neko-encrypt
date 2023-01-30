use std::fs;
//use std::io;
use std::io::prelude::*;

use rand::Rng;
use sha3::Digest;

#[allow(non_upper_case_globals)]
pub const suffix: &str = ".neko";

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub struct encryp_option {
    pub keep: bool,
    pub cover_existing_file: bool,
    pub buffer_size: usize,
    pub password: String,
    pub salt_a: Vec<u8>,
    pub salt_b: Vec<u8>,
}

#[repr(u64)]
#[allow(non_camel_case_types)]
#[derive(Eq, Hash, PartialEq, Debug)]
pub enum data_block_type {
    salt_a = 42,
    salt_b = 114514,
    hash_password = 1919810,
    ciphertext = 666,
    sha3_512_original_file = 2300,
}

impl encryp_option {
    pub fn create(
        keep: bool,
        cover_existing_file: bool,
        password: &String,
        buffer_size: usize,
    ) -> encryp_option {
        let mut rng = rand::thread_rng();

        let salt_a: u128 = rng.gen();
        let salt_a = salt_a.to_le_bytes().to_vec();

        let salt_b: u128 = rng.gen();
        let salt_b = salt_b.to_le_bytes().to_vec();

        let ret = encryp_option {
            keep: keep,
            cover_existing_file: cover_existing_file,
            password: password.clone(),
            salt_a: salt_a,
            salt_b: salt_b,
            buffer_size: buffer_size,
        };

        return ret;
    }
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

    let dst_exist: bool;

    {
        let file = fs::File::open(dst_name);
        dst_exist = file.is_ok();
    }

    if dst_exist && (!opt.cover_existing_file) {
        return Err(String::from("Error : destination file already exists."));
    }

    let ifile = fs::File::open(src_name);
    if !ifile.is_ok() {
        return Err(String::from("Error : failed to open source file."));
    }

    //let mut ifile = ifile.as_ref().unwrap();

    let ofile = fs::OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open(dst_name);

    if !ofile.is_ok() {
        return Err(String::from("Error : failed to open/create dest file"));
    }

    //let mut ofile = ofile.as_ref().unwrap();

    return Ok(file_streams_pair {
        ifile: (ifile.unwrap()),
        ofile: (ofile.unwrap()),
    });
}

#[allow(non_upper_case_globals)]
const file_head: [u8; 16] = [
    0,
    0,
    ('T' as u8),
    ('e' as u8),
    ('n' as u8),
    ('t' as u8),
    4,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

fn write_data_block_head(ofile: &mut fs::File, data_type: data_block_type, len: u64) {
    ofile
        .write((data_type as u64).to_le_bytes().as_slice())
        .unwrap();
    ofile.write(len.to_le_bytes().as_slice()).unwrap();
}

fn write_data_block(ofile: &mut fs::File, data_type: data_block_type, data_u8: &[u8]) {
    write_data_block_head(ofile, data_type, data_u8.len() as u64);

    ofile.write(data_u8).unwrap();
}

fn compute_initial_x(opt: &encryp_option) -> u64 {
    let mut x_beg: u64;
    {
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(opt.password.as_bytes());
        hasher.update(opt.salt_b.as_slice());

        let hash_ptr: *const u64 = hasher.finalize().as_ptr() as *const u64;

        unsafe {
            x_beg = *hash_ptr;

            let mut i = 1;

            loop {
                if i >= 8 {
                    break;
                }

                x_beg = x_beg ^ (*hash_ptr.add(i));

                i += 1;
            }
        }
    }

    return x_beg;
}

pub fn encryp_file(src_name: &String, dst_name: &String, opt: &encryp_option) -> bool {
    let streams = create_file_stream(src_name, dst_name, opt);
    if streams.is_err() {
        println!("{:?}", streams.err());
        return false;
    }

    let streams = streams.unwrap();

    let mut ofile = streams.ofile;

    ofile.write(file_head.as_slice()).unwrap();
    //write salt A
    write_data_block(&mut ofile, data_block_type::salt_a, &opt.salt_a.as_slice());

    //write salt B
    write_data_block(&mut ofile, data_block_type::salt_b, &opt.salt_b.as_slice());
    //write hashed password (sha3-512)
    {
        let mut hasher_password = sha3::Sha3_512::new();
        hasher_password.update(opt.password.as_bytes());
        hasher_password.update(opt.salt_a.as_slice());

        let hash_psw = hasher_password.finalize().to_vec();

        write_data_block(
            &mut ofile,
            data_block_type::hash_password,
            hash_psw.as_slice(),
        );
    }
    let buffer_size: usize = opt.buffer_size;

    let mut buffer: Vec<u8> = Vec::new();
    buffer.resize(buffer_size, 0xFF);

    let mut ifile = streams.ifile;
    {
        let file_size: u64 = ifile.metadata().unwrap().len();
        write_data_block_head(&mut ofile, data_block_type::ciphertext, file_size);
    }

    let x_beg: u64 = compute_initial_x(&opt);

    let mut tent = tent_chaos::new(x_beg);

    let mut hasher = sha3::Sha3_512::new();

    loop {
        //loop {
        let read_bytes = ifile.read(&mut buffer).unwrap();

        hasher.update(&buffer[0..read_bytes]);

        let read_bytes_ceil: usize = {
            if read_bytes % 8 == 0 {
                read_bytes
            } else {
                (read_bytes | 0b111) + 1
                //buffer_size
            }
        };

        //println!("read_bytes_ceil")

        tent.encrypt(&mut buffer[0..read_bytes_ceil]).unwrap();

        //println!("{read_bytes} bytes read");

        ofile.write(&buffer[0..read_bytes]).unwrap();
        //}
        //println!("{wrote_bytes} bytes wrote");

        if read_bytes < buffer_size {
            break;
        }
    }

    write_data_block(
        &mut ofile,
        data_block_type::sha3_512_original_file,
        &hasher.finalize().to_vec(),
    );

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
                        *(data.add(it as usize)) ^= x.0;
                    } else {
                        *(data.add(it as usize)) = x.0;
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
            let mut err_msg =
                String::from("Length of u8 array should be multiples of 8, but actually it is ");

            err_msg.push_str(vec.len().to_string().as_str());
            return Err(err_msg);
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

//use hex_literal::hex;

pub fn test_checksum(filename: &String) {
    let mut ifile = fs::File::open(filename).unwrap();

    let mut buffer: [u8; 65536] = [0; 65536];

    let buffer_bytes = buffer.len();

    let mut hasher = sha3::Sha3_512::new();

    loop {
        let bytes_read = ifile.read(buffer.as_mut_slice()).unwrap();

        hasher.update(buffer[0..bytes_read].as_ref());

        if bytes_read < buffer_bytes {
            break;
        }
    }

    let result = hasher.finalize();

    println!("result = {:?}", result);
}

use std::collections::HashMap;

#[allow(non_camel_case_types)]
#[derive(Debug)]
enum data_block_data {
    small(Vec<u8>),
    large(u64),
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
struct data_block_content {
    data: data_block_data,
    offset: u64,
}

#[allow(non_camel_case_types)]
struct encrypted_file {
    data_blocks: HashMap<data_block_type, data_block_content>,
}

fn parse_encrypted_file(ifile: &mut fs::File) -> Result<encrypted_file, String> {
    let mut file = encrypted_file {
        data_blocks: HashMap::new(),
    };

    let mut buffer: Vec<u8> = Vec::new();
    buffer.reserve(512);

    buffer.resize(16, 0xFF);
    {
        let ret = ifile.read_exact(buffer.as_mut_slice());
        if ret.is_err() {
            return Err(String::from("Failed to read file head."));
        }

        if buffer.len() != 16 {
            return Err(String::from("length of buffer is not 16."));
        }
    }

    for i in 0..=4 {
        let idx = i as usize;
        if buffer[idx] != file_head[idx] {
            return Err(String::from("File head mismatch."));
        }
    }

    loop {
        let mut blk_type: data_block_type = data_block_type::ciphertext;
        let blk_len: u64;

        let is_block_unknown: bool;

        buffer.resize(16, 0xFF);

        let ret = ifile.read(buffer.as_mut_slice());

        if ret.is_err() {
            return Err(String::from("Failed to read a data block."));
        } else {
            let bytes: usize = ret.unwrap();
            if bytes == 0 {
                break;
            }
            if bytes != 16 {
                return Err(String::from("Imcomplete data block."));
            }
        }

        //blk_type = u64::from_le_bytes(buffer.);

        unsafe {
            let ptr: *const u64 = buffer.as_ptr() as *const u64;
            blk_len = *(ptr.add(1));

            let mut temp: data_block_type = data_block_type::sha3_512_original_file;

            let ptr_temp = ((&mut temp) as *mut data_block_type) as *mut u64;

            //let ptr_type: *mut u64 = (&mut blk_type) as *mut data_block_type as *mut u64;
            *ptr_temp = *ptr;

            match temp {
                data_block_type::ciphertext
                | data_block_type::hash_password
                | data_block_type::salt_a
                | data_block_type::salt_b
                | data_block_type::sha3_512_original_file => {
                    is_block_unknown = false;
                    blk_type = temp;
                }
                #[allow(unreachable_patterns)]
                _ => {
                    println!("Warning : unknown data block {}", temp as u64);
                    is_block_unknown = true;
                }
            }

            //let ptr_len: *mut u64 = (&mut blk_len) as *mut u64;
        }

        let load_full_block: bool;

        if is_block_unknown {
            load_full_block = true;
        } else {
            match blk_type {
                data_block_type::ciphertext => {
                    load_full_block = false;
                }
                _ => load_full_block = true,
            }
            //load_full_block = (blk_type != data_block_type::ciphertext);
        }

        if is_block_unknown {
            ifile
                .seek(std::io::SeekFrom::Current(blk_len as i64))
                .expect("Failed to seek");
            continue;
        }

        if file.data_blocks.contains_key(&blk_type) {
            return Err(String::from("More than one block have the same tag."));
        }

        let blk_data: data_block_data;

        let offset: u64 = ifile
            .stream_position()
            .expect("Failed to tell stream position");

        if load_full_block {
            buffer.resize(blk_len as usize, 0xFF);

            ifile
                .read_exact(buffer.as_mut())
                .expect("Unfinished data block");

            blk_data = data_block_data::small(buffer.clone());
        } else {
            ifile
                .seek(std::io::SeekFrom::Current(blk_len as i64))
                .expect("Failed to seek");
            blk_data = data_block_data::large(blk_len);
        }

        file.data_blocks.insert(
            blk_type,
            data_block_content {
                data: blk_data,
                offset: offset,
            },
        );
    }

    return Ok(file);
}

fn get_salt(opt: &mut encryp_option, efile: &encrypted_file) -> Result<(), ()> {
    // get salt_a
    match efile.data_blocks.get(&data_block_type::salt_a) {
        Some(content) => match &content.data {
            data_block_data::small(v) => {
                opt.salt_a = v.clone();
            }
            _ => {
                eprintln!("{:?}", content.data);
                return Err(());
            }
        },
        None => {
            eprintln!(
                "File does not have data block {:?}",
                data_block_type::salt_a
            );
            return Err(());
        }
    }

    match efile.data_blocks.get(&data_block_type::salt_b) {
        Some(content) => match &content.data {
            data_block_data::small(v) => {
                opt.salt_b = v.clone();
            }
            _ => {
                eprintln!("{:?}", content.data);
                return Err(());
            }
        },
        None => {
            eprintln!(
                "File does not have data block {:?}",
                data_block_type::salt_b
            );
            return Err(());
        }
    }

    return Ok(());
}

fn get_hashes(efile: &encrypted_file) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let mut ret: (Vec<u8>, Vec<u8>) = (Vec::new(), Vec::new());
    // hash_password
    match efile.data_blocks.get(&data_block_type::hash_password) {
        Some(content) => match &content.data {
            data_block_data::small(v) => {
                ret.0 = v.clone();
            }
            _ => {
                eprintln!("{:?}", content.data);
                return Err(());
            }
        },
        None => {
            eprintln!(
                "File does not have data block {:?}",
                data_block_type::hash_password
            );
            return Err(());
        }
    }

    //original hash
    match efile
        .data_blocks
        .get(&data_block_type::sha3_512_original_file)
    {
        Some(content) => match &content.data {
            data_block_data::small(v) => {
                ret.1 = v.clone();
            }
            _ => {
                eprintln!("{:?}", content.data);
                return Err(());
            }
        },
        None => {
            eprintln!(
                "File does not have data block {:?}",
                data_block_type::sha3_512_original_file
            );
            return Err(());
        }
    }

    return Ok(ret);
}

fn exmaine_password(opt: &encryp_option, password_hash: &Vec<u8>) -> bool {
    let mut hasher = sha3::Sha3_512::new();

    hasher.update(&opt.password);
    hasher.update(&opt.salt_a);
    let ret = hasher.finalize();

    if ret.len() != password_hash.len() {
        return false;
    }

    for idx in 0..ret.len() {
        let idx = idx as usize;
        if ret[idx] != password_hash[idx] {
            return false;
        }
    }
    return true;
}
#[allow(non_camel_case_types)]
struct ciphertext_info {
    length: u64,
    offset: u64,
}

//(lenght,offset)
fn get_ciphertext_info(efile: &encrypted_file) -> Result<ciphertext_info, ()> {
    let mut ret: ciphertext_info = ciphertext_info {
        length: 0,
        offset: 0,
    };

    match efile.data_blocks.get(&data_block_type::ciphertext) {
        Some(content) => {
            ret.offset = content.offset;

            match &content.data {
                data_block_data::large(bytes) => {
                    ret.length = *bytes;
                }
                _ => {
                    return Err(());
                }
            }
        }
        None => {
            return Err(());
        }
    }

    return Ok(ret);
}

use std::cmp::min;

pub fn decrypt_file(src_name: &String, __opt: &encryp_option, dst_dst_name: &mut String) -> bool {
    let mut opt: encryp_option = __opt.clone();

    if !src_name.ends_with(suffix) {
        eprintln!(
            "Fatal error : extension of source file {} is not {}.",
            src_name, suffix
        );
        return false;
    }

    let dst_name = &src_name[0..(src_name.len() - suffix.len())];

    *dst_dst_name = String::from(dst_name);

    let streams = create_file_stream(src_name, dst_dst_name, __opt);
    if streams.is_err() {
        println!("{:?}", streams.err());
        return false;
    }

    let streams = streams.unwrap();

    let mut ifile = streams.ifile;

    let efile = parse_encrypted_file(&mut ifile);

    if efile.is_err() {
        eprintln!("{}", efile.err().unwrap());
        return false;
    }

    let efile = efile.unwrap();

    if get_salt(&mut opt, &efile).is_err() {
        return false;
    }

    let hashes = get_hashes(&efile);
    if hashes.is_err() {
        return false;
    }

    let hashes = hashes.unwrap();

    if !exmaine_password(&opt, &hashes.0) {
        println!(
            "Error : Failed to decrypt file {} : Wrong password.",
            src_name
        );
        return false;
    }

    let mut hasher = sha3::Sha3_512::new();

    let mut buffer: Vec<u8> = Vec::new();

    buffer.resize(opt.buffer_size, 0xFF);

    let mut ofile = streams.ofile;

    let cipher_info = get_ciphertext_info(&efile);

    if cipher_info.is_err() {
        eprintln!(
            "Failed to decrypt file {} : cipher text not found.",
            src_name
        );
        return false;
    }

    let cipher_info = cipher_info.unwrap();

    ifile
        .seek(std::io::SeekFrom::Start(cipher_info.offset))
        .expect("Failed to seek.");

    let mut total_read: u64 = 0;

    let mut tent = tent_chaos::new(compute_initial_x(&opt));

    loop {
        let bytes_read = ifile.read(buffer.as_mut());

        if let Err(err) = bytes_read {
            eprintln!("Failed to read from file {}, detail : {:?}", src_name, err);
            return false;
        }

        let bytes_read = bytes_read.unwrap();

        let bytes_avaliable: u64 = min(bytes_read as u64, cipher_info.length - total_read);

        total_read += bytes_read as u64;

        let bytes_avaliable_ceil: usize = {
            if bytes_avaliable % 8 == 0 {
                bytes_avaliable as usize
            } else {
                (bytes_avaliable as usize | 0b111) + 1
                //buffer_size
            }
        };

        tent.encrypt(&mut buffer[0..bytes_avaliable_ceil])
            .expect("Tent chaos failed to decrpyt.");

        hasher.update(&buffer[0..bytes_avaliable as usize]);

        ofile
            .write(&buffer[0..bytes_avaliable as usize])
            .expect("Failed to write.");

        if total_read >= cipher_info.length {
            break;
        }
    }

    let sha3_512_file = hasher.finalize();

    if sha3_512_file.len() != hashes.1.len() {
        eprintln!(
            "Lenght of hash mismatch : {} and {}",
            sha3_512_file.len(),
            hashes.1.len()
        );

        return false;
    }

    for i in 0..sha3_512_file.len() {
        let i = i as usize;

        if sha3_512_file[i] != hashes.1[i] {
            eprintln!("Failed to decrpyt file : sha3-512 checksum failed.");
            return false;
        }
    }

    println!("success");

    /*
    for blk in efile.unwrap().data_blocks {
        println!("key = {:?}, value = {:?}", blk.0, blk.1);
    }

    */

    //println!("src = {}, dst = {}", src_name, dst_name);

    return true;
}
