# simple-xor

> **Maximum reliability streaming XOR tool (Linux only)**

A robust, production-grade command-line utility for performing bitwise XOR between an input file and a key file. Designed from the ground up for **data integrity**, **atomic commits**, **full durability**, and **strong verification** — even in the face of crashes, power loss, or concurrent access.

---

## Features

- **True streaming processing** — Constant 1 MiB memory usage regardless of file size
- **Atomic commit** via `renameat2(..., RENAME_NOREPLACE)` — output file either appears fully formed or not at all; never overwrites an existing file
- **Full durability** — `fsync()` on the written data **and** `fsync()` on the parent directory
- **Strong verification mode** (`--verify`) — complete round-trip re-XOR + byte-for-byte comparison + length + no-trailing-garbage checks
- **Race-free temporary files** created with `O_EXCL` + PID-based unique naming
- **Aggressive cleanup** — temporary files are removed on every error path
- **Minimal unsafe Rust** — only the Linux `renameat2` syscall is called via `unsafe`

## When Should You Use It?

Use `simple-xor` when you need **maximum guarantees** that:

- Either the output is 100% correct and durably on disk, **or** nothing was written
- Partial/torn files are impossible
- Concurrent runs or sudden power loss cannot corrupt your data
- You want cryptographic-strength *verification* (not just checksums) that the transformation succeeded

Perfect for critical data pipelines, secure backup scripts, air-gapped file transfer, or any situation where "it mostly worked" is unacceptable.

## Requirements

- Linux kernel ≥ 3.15 (for `renameat2`)
- Rust 1.70+ (for building)

## Building & Installation

```bash
# Build optimized binary
cargo build --release

# Optional: install system-wide
sudo install -m 755 target/release/simple-xor /usr/local/bin/simple-xor
```

## Usage

```bash
simple-xor <input_file> <key_file> <output_file> [--verify]
```

### Rules

| Rule                        | Reason                                      |
|----------------------------|---------------------------------------------|
| Output must **not** exist  | Prevents accidental data loss               |
| Key ≥ input size (bytes)   | Streaming read; no padding or truncation    |
| Linux only                 | Uses Linux-specific syscalls                |

### Examples

```bash
# Basic usage (no verification)
simple-xor plaintext.bin key.bin ciphertext.xor

# Recommended: full verification before commit
simple-xor secrets.tar.gz otp.key secrets.tar.gz.xor --verify

# Safe pipeline pattern
simple-xor input.bin key.bin output.bin --verify \
  && rm -f input.bin key.bin
```

## The `--verify` Flag — What It Actually Does

When enabled, **before** the atomic rename happens:

1. Stat the temporary file and compare length to original input
2. Re-open all three files and stream:
   - Read chunk from output
   - Read same-sized chunk from key
   - XOR them together
   - Compare result byte-for-byte with original input chunk
3. After processing everything, ensure **zero extra bytes** remain in the output (rejects trailing garbage)
4. Only if **every single byte** matches and lengths are identical does the tool proceed to atomically commit the file

This is far stronger than a simple hash check — it proves the XOR operation was performed correctly end-to-end.

## Exit Codes

| Exit Code | Meaning                                      |
|-----------|----------------------------------------------|
| 0         | Success — output committed and durable       |
| 1         | Usage error, I/O error, or rename failure    |
| 2         | Verification failed (`--verify` mode only)   |

## Technical Highlights

| Aspect                    | Implementation                                      |
|---------------------------|-----------------------------------------------------|
| Buffering                 | `BufReader` / `BufWriter` with 1 MiB capacity       |
| Temp file creation        | `OpenOptions::create_new(true)` (O_EXCL)            |
| Atomic replace            | `renameat2(AT_FDCWD, ..., RENAME_NOREPLACE)`        |
| Durability                | `sync_all()` on file + parent directory             |
| Error handling            | Every failure path removes temp file                |
| Verification              | Full re-XOR + memcmp + length + EOF check           |
| C string handling         | `CString` with proper error on invalid UTF-8        |

## Security & Cryptography Warning

**Raw XOR is not modern encryption.**

It only provides meaningful confidentiality when used as a **one-time pad**:

- Key must be truly random
- Key must be ≥ plaintext length
- Key must **never** be reused
- Key must be kept secret and deleted after use

For real security, use `age`, `gpg --symmetric`, or libraries such as `rustls` / `ring`.

`simple-xor` is best suited for:
- Data obfuscation / whitening
- Combining multiple transforms
- Educational purposes
- Controlled environments where you already manage key material securely

## License

MIT License — see `Cargo.toml` for details.

You are free to use, modify, fork, and redistribute this tool.

---

*Crafted with obsessive attention to correctness, atomicity, and durability. If you discover any way to make the reliability guarantees even stronger, feel free to open an issue or pull request.*
