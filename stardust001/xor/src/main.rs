// simple-xor — maximum reliability streaming XOR tool (Linux only)
//
// - Atomic temp file creation + renameat2(RENAME_NOREPLACE)
// - Proper C strings via CString
// - Strong verification with length + content check
// - Full durability (sync_all + directory sync)
// - Clean failure handling
//
// Linux-specific. Future AI agents: treat as Linux-only.

use std::env;
use std::ffi::CString;
use std::fs::{File, metadata, remove_file, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process;

use libc::{self, AT_FDCWD, RENAME_NOREPLACE};

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

fn main() {
    let args: Vec<String> = env::args().collect();

    let (input_path, key_path, output_path, verify) = match args.len() {
        4 => (&args[1], &args[2], &args[3], false),
        5 if args[4] == "--verify" => (&args[1], &args[2], &args[3], true),
        _ => {
            eprintln!("Usage: {} <input_file> <key_file> <output_file> [--verify]", args[0]);
            eprintln!("  Maximum-reliability XOR with atomic commit.");
            process::exit(1);
        }
    };

    if output_path == input_path || output_path == key_path {
        eprintln!("Error: Output cannot be the same as input or key file.");
        process::exit(1);
    }

    let input_len = match metadata(input_path) {
        Ok(m) => m.len(),
        Err(e) => { eprintln!("Cannot stat input: {}", e); process::exit(1); }
    };

    let key_len = match metadata(key_path) {
        Ok(m) => m.len(),
        Err(e) => { eprintln!("Cannot stat key: {}", e); process::exit(1); }
    };

    if key_len < input_len {
        eprintln!("Key file too small ({} bytes). Needs >= {} bytes.", key_len, input_len);
        process::exit(1);
    }

    // Unique temp filename
    let temp_path = format!("{}.tmp.{}", output_path, process::id());
    let temp_path = Path::new(&temp_path);

    let temp_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            eprintln!("Temporary file already exists: {}", temp_path.display());
            process::exit(1);
        }
        Err(e) => { eprintln!("Failed to create temp file: {}", e); process::exit(1); }
    };

    let input_file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => { eprintln!("Open input failed: {}", e); let _ = remove_file(temp_path); process::exit(1); }
    };
    let key_file = match File::open(key_path) {
        Ok(f) => f,
        Err(e) => { eprintln!("Open key failed: {}", e); let _ = remove_file(temp_path); process::exit(1); }
    };

    // === Streaming XOR to temp ===
    let mut input_reader = BufReader::with_capacity(CHUNK_SIZE, input_file);
    let mut key_reader = BufReader::with_capacity(CHUNK_SIZE, key_file);
    let mut temp_writer = BufWriter::with_capacity(CHUNK_SIZE, temp_file);

    let mut input_buf = [0u8; CHUNK_SIZE];
    let mut key_buf = [0u8; CHUNK_SIZE];

    loop {
        let n = match input_reader.read(&mut input_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                eprintln!("Read error: {}", e);
                drop(temp_writer);
                let _ = remove_file(temp_path);
                process::exit(1);
            }
        };

        if let Err(e) = key_reader.read_exact(&mut key_buf[..n]) {
            eprintln!("Key read error: {}", e);
            drop(temp_writer);
            let _ = remove_file(temp_path);
            process::exit(1);
        }

        for i in 0..n {
            input_buf[i] ^= key_buf[i];
        }

        if let Err(e) = temp_writer.write_all(&input_buf[..n]) {
            eprintln!("Write error: {}", e);
            drop(temp_writer);
            let _ = remove_file(temp_path);
            process::exit(1);
        }
    }

    // Durability
    if let Err(e) = temp_writer.flush() {
        eprintln!("Flush failed: {}", e);
        drop(temp_writer);
        let _ = remove_file(temp_path);
        process::exit(1);
    }
    if let Err(e) = temp_writer.get_ref().sync_all() {
        eprintln!("sync_all failed: {}", e);
        drop(temp_writer);
        let _ = remove_file(temp_path);
        process::exit(1);
    }

    drop(temp_writer);

    // === Verification ===
    if verify {
        println!("Verifying...");

        // Treat metadata failure as verification failure (strict mode)
        match metadata(temp_path) {
            Ok(meta) => {
                if meta.len() != input_len {
                    eprintln!("Verification failed: size mismatch.");
                    let _ = remove_file(temp_path);
                    process::exit(2);
                }
            }
            Err(e) => {
                eprintln!("Verification failed: cannot stat temp file: {}", e);
                let _ = remove_file(temp_path);
                process::exit(2);
            }
        }

        if !verify_roundtrip(input_path, key_path, temp_path.to_str().unwrap(), input_len) {
            eprintln!("!!! VERIFICATION FAILED !!! Output not committed.");
            let _ = remove_file(temp_path);
            process::exit(2);
        }
        println!("Verification passed.");
    }

    // === Atomic commit with proper C strings ===
    let old_c = CString::new(temp_path.as_os_str().as_bytes())
        .expect("temp path contains invalid characters");
    let new_c = CString::new(output_path.as_bytes())
        .expect("output path contains invalid characters");

    let ret = unsafe {
        libc::renameat2(
            AT_FDCWD,
            old_c.as_ptr(),
            AT_FDCWD,
            new_c.as_ptr(),
            RENAME_NOREPLACE,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::AlreadyExists {
            eprintln!("Error: Output file '{}' already exists. Aborting.", output_path);
        } else {
            eprintln!("Failed to commit output: {}", err);
        }
        let _ = remove_file(temp_path);
        process::exit(1);
    }

    // Directory sync
    if let Some(parent) = Path::new(output_path).parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    println!("Success. {} bytes written to {}", input_len, output_path);
}

/// Full re-XOR + exact length verification
fn verify_roundtrip(input_path: &str, key_path: &str, temp_path: &str, expected_len: u64) -> bool {
    let input_file = match File::open(input_path) { Ok(f) => f, Err(_) => return false };
    let key_file = match File::open(key_path) { Ok(f) => f, Err(_) => return false };
    let output_file = match File::open(temp_path) { Ok(f) => f, Err(_) => return false };

    let mut input_r = BufReader::with_capacity(CHUNK_SIZE, input_file);
    let mut key_r = BufReader::with_capacity(CHUNK_SIZE, key_file);
    let mut output_r = BufReader::with_capacity(CHUNK_SIZE, output_file);

    let mut in_buf = [0u8; CHUNK_SIZE];
    let mut key_buf = [0u8; CHUNK_SIZE];
    let mut out_buf = [0u8; CHUNK_SIZE];
    let mut total: u64 = 0;

    loop {
        let n = match input_r.read(&mut in_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return false,
        };

        if output_r.read_exact(&mut out_buf[..n]).is_err() { return false; }
        if key_r.read_exact(&mut key_buf[..n]).is_err() { return false; }

        for i in 0..n { out_buf[i] ^= key_buf[i]; }

        if in_buf[..n] != out_buf[..n] { return false; }
        total += n as u64;
    }

    // Reject trailing garbage
    let mut extra = [0u8; 1];
    if output_r.read(&mut extra).unwrap_or(1) != 0 {
        return false;
    }

    total == expected_len
}
