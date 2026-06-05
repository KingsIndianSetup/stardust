 // =============================================================================
// tools — Deterministic key generation + high-reliability streaming XOR
// Single-file Linux CLI tool
// =============================================================================
// Force Linux-only compilation.
// We use Linux-specific syscalls (renameat2) for atomic file replacement.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "This tool only supports Linux. It uses the Linux-specific renameat2 syscall \
     for safe atomic file replacement."
);
use std::env;
use std::ffi::CString;
use std::fs::{File, metadata, remove_file, OpenOptions, canonicalize};
use std::io::{self, BufReader, BufWriter, Read, Write, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process;
use clap::{Parser, Subcommand};
use libc::{self, AT_FDCWD};
use rpassword::prompt_password;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
// =============================================================================
// Shared helper: always use key.key next to the executable
// =============================================================================
fn default_key_path() -> std::path::PathBuf {
    let mut path = env::current_exe().expect("Failed to get executable path");
    path.pop();
    path.push("key.key");
    path
}
// =============================================================================
// KEYGEN
// =============================================================================
mod keygen {
    use super::*;
    pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
    pub const MAX_SIZE: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
    #[derive(Parser, Debug)]
    #[command(about = "Deterministic key generator: password → reproducible keystream. Always writes to 'key.key' next to the executable (silently overwrites if it exists).")]
    pub struct Args {
        /// Key size in bytes (1 to 20 GiB)
        #[arg(index = 1)]
        pub size: u64,
        /// Optional context (e.g. "github", "backup-2026")
        #[arg(short, long)]
        pub context: Option<String>,
    }
    pub fn run(args: Args) -> io::Result<()> {
        if args.size == 0 || args.size > MAX_SIZE {
            eprintln!("Error: Size must be between 1 and 20 GiB.");
            std::process::exit(1);
        }
        // Always use key.key next to the executable.
        // We now silently overwrite if it already exists (atomic replace).
        let output_path = default_key_path();
        // ========================
        // PASSWORD INPUT
        // ========================
        let pw1 = prompt_password("Enter password: ")?;
        let pw2 = prompt_password("Confirm password: ")?;
        if pw1 != pw2 {
            eprintln!("Error: Passwords do not match.");
            std::process::exit(1);
        }
        let mut password = pw1.into_bytes();
        // ========================
        // CONTEXT (acts like salt)
        // ========================
        let context = args.context.unwrap_or_else(|| "default".into());
        // Combine password + context
        let mut input = password.clone();
        input.extend_from_slice(context.as_bytes());
        // ========================
        // ARGON2 → MASTER KEY
        // ========================
        let mut master_key = [0u8; 32];
        let params = Params::new(
            131_072, // 128 MB memory
            3, // iterations
            4, // parallelism
            None,
        ).expect("Invalid Argon2 params");
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        );
        // Deterministic salt derived from context
        let salt = Sha256::digest(format!("stardust-salt:{}", context));
        argon2
            .hash_password_into(&input, &salt, &mut master_key)
            .expect("Argon2 failed");
        // ========================
        // DOMAIN SEPARATION
        // ========================
        // stream_key = SHA256(master_key || "stream")
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(b"stream");
        let stream_key = hasher.finalize();
        // nonce = first 12 bytes of SHA256(master_key || "nonce")
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(b"nonce");
        let nonce_hash = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_hash[..12]);
        // Convert stream_key to fixed-size array
        let key: [u8; 32] = stream_key[..32]
            .try_into()
            .expect("Invalid key length");
        // ========================
        // CHACHA20 SETUP
        // ========================
        let mut cipher = ChaCha20::new(
            &key.into(),
            &nonce.into(),
        );
        // ========================
        // STREAM GENERATION (atomic + durable write)
        // ========================
        let temp_path = format!("{}.tmp.{}", output_path.display(), process::id());
        let temp_path = Path::new(&temp_path);
        let temp_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp_path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                eprintln!("Temporary file already exists: {}", temp_path.display());
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Failed to create temp file: {}", e);
                std::process::exit(1);
            }
        };
        let mut output = BufWriter::with_capacity(CHUNK_SIZE, temp_file);
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut remaining = args.size;
        while remaining > 0 {
            let chunk = std::cmp::min(CHUNK_SIZE as u64, remaining) as usize;
            cipher.apply_keystream(&mut buffer[..chunk]);
            output.write_all(&buffer[..chunk])?;
            remaining -= chunk as u64;
        }
        // Durability
        if let Err(e) = output.flush() {
            eprintln!("Flush failed: {}", e);
            let _ = remove_file(temp_path);
            std::process::exit(1);
        }
        if let Err(e) = output.get_ref().sync_all() {
            eprintln!("sync_all failed: {}", e);
            let _ = remove_file(temp_path);
            std::process::exit(1);
        }
        drop(output);
        // Atomic commit using renameat2.
        // We intentionally allow replacing an existing file (silent overwrite for keygen).
        let old_c = CString::new(temp_path.as_os_str().as_bytes())
            .expect("temp path contains invalid characters");
        let new_c = CString::new(output_path.as_os_str().as_bytes())
            .expect("output path contains invalid characters");
        let ret = unsafe {
            libc::renameat2(
                AT_FDCWD,
                old_c.as_ptr(),
                AT_FDCWD,
                new_c.as_ptr(),
                0, // 0 = allow replacement of existing target
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("Failed to commit output file: {}", err);
            let _ = remove_file(temp_path);
            std::process::exit(1);
        }
        // Directory sync for durability
        if let Some(parent) = output_path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        // ========================
        // CLEANUP (basic memory wipe)
        // ========================
        password.fill(0);
        master_key.fill(0);
        Ok(())
    }
}
// =============================================================================
// XOR
// =============================================================================
mod xor {
    use super::*;
    pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB
    #[derive(Parser, Debug)]
    #[command(about = "High-reliability in-place streaming XOR using key.key (next to binary). Always verifies before committing. Linux only.")]
    pub struct Args {
        /// File to XOR in place (will be atomically replaced)
        #[arg(index = 1)]
        pub input: String,
    }
    pub fn run(args: Args) {
        let input_path = &args.input;
        let key_path = default_key_path();
        // Early check for key existence with helpful message
        if !key_path.exists() {
            eprintln!("Error: Key file does not exist: {:?}", key_path);
            eprintln!("Run 'tools keygen <size> [--context <name>]' first to create it.");
            process::exit(1);
        }
        // =====================================================================
        // ROBUST SELF-PROTECTION (the bug fix)
        // =====================================================================
        // We must prevent XORing the key file with itself under ANY path
        // representation (relative "key.key", absolute, via symlink, ../ etc).
        // A successful self-XOR would replace the key with all-zeroes
        // (because verification does round-trip and would "pass" since
        // original XOR key == zero, and re-XOR zero with key recovers original).
        // Only keygen is allowed to overwrite key.key (intentionally, atomically).
        let key_canonical = match canonicalize(&key_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error: Failed to resolve key path {:?}: {}", key_path, e);
                process::exit(1);
            }
        };
        if let Ok(input_canonical) = canonicalize(Path::new(input_path)) {
            if input_canonical == key_canonical {
                eprintln!("Error: key.key cannot be XORed with key.key");
                eprintln!("The key file is protected from modification by the 'xor' command.");
                eprintln!("Use 'keygen' if you want to replace/create a new key.key (it safely overwrites).");
                process::exit(1);
            }
        }
        let input_len = match metadata(input_path) {
            Ok(m) => m.len(),
            Err(e) => { eprintln!("Cannot stat input: {}", e); process::exit(1); }
        };
        let key_len = match metadata(&key_path) {
            Ok(m) => m.len(),
            Err(e) => { eprintln!("Cannot stat key file: {}", e); process::exit(1); }
        };
        if key_len < input_len {
            eprintln!("Key file too small ({} bytes). Needs >= {} bytes.", key_len, input_len);
            process::exit(1);
        }
        // Unique temp filename next to the input file (for atomic replace on same filesystem)
        let temp_path = format!("{}.tmp.{}", input_path, process::id());
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
        let key_file = match File::open(&key_path) {
            Ok(f) => f,
            Err(e) => { eprintln!("Open key file {:?} failed: {}", key_path, e); let _ = remove_file(temp_path); process::exit(1); }
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
        // === ALWAYS verify before committing (in-place safety) ===
        println!("Verifying...");
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
        if !verify_roundtrip(input_path, key_path.to_str().expect("key path is not valid UTF-8"), temp_path.to_str().unwrap(), input_len) {
            eprintln!("!!! VERIFICATION FAILED !!! Original file left untouched.");
            let _ = remove_file(temp_path);
            process::exit(2);
        }
        println!("Verification passed.");
        // === Atomic commit: replace the original input file ===
        let old_c = CString::new(temp_path.as_os_str().as_bytes())
            .expect("temp path contains invalid characters");
        let new_c = CString::new(input_path.as_bytes())
            .expect("input path contains invalid characters");
        let ret = unsafe {
            libc::renameat2(
                AT_FDCWD,
                old_c.as_ptr(),
                AT_FDCWD,
                new_c.as_ptr(),
                0, // allow atomic replacement of existing file
            )
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("Failed to commit output: {}", err);
            let _ = remove_file(temp_path);
            process::exit(1);
        }
        // Directory sync
        if let Some(parent) = Path::new(input_path).parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        println!("operation complete");
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
}
// =============================================================================
// MAIN
// =============================================================================
#[derive(Parser)]
#[command(
    name = "tools",
    about = None,
    long_about = None,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_required = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// Generate deterministic keystream from password (up to 20 GiB). Silently overwrites key.key if present.
    Keygen(keygen::Args),
    /// In-place XOR using key.key (next to binary). Always verifies. Command: tools xor <file>
    Xor(xor::Args),
}
fn main() {
    // If no subcommand is provided, exit silently (no Usage/Commands output)
    if std::env::args().len() == 1 {
        std::process::exit(0);
    }
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen(args) => {
            if let Err(e) = keygen::run(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Xor(args) => {
            xor::run(args);
        }
    }
}
