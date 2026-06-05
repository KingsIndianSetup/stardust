# stardust9

A small, high-quality Linux command-line tool for **deterministic key generation** and **maximum-reliability streaming XOR**.

The entire tool is contained in a single `main.rs` file.

## Features

- **Single binary** (`stardust9`)
- Two subcommands: `keygen` and `xor`
- Strong focus on **data safety** and **reliability**
- Atomic file operations using `renameat2(RENAME_NOREPLACE)`
- Full durability with `fsync()` on file and directory
- Optional strong verification mode for XOR operations
- Minimal output when run with no arguments (refined CLI behavior)

## Installation


git clone https://github.com//KingsIndianSetup/stardust9

cd xor-stardust9/stardust9

cargo build --release


The binary will be at `target/release/stardust9`.

You can optionally install it:


sudo install -m 755 target/release/stardust9 /usr/local/bin/stardust9


## Usage

### `keygen` — Deterministic Keystream Generator

Generate a reproducible keystream from a password using Argon2id + ChaCha20.


stardust9 keygen <size_in_bytes> [--context <string>] [--output <path>]


**Examples:**


stardust9 keygen 1073741824
stardust9 keygen 21474836480 --context "backup-2026" --output mykey.bin


- Maximum size: 20 GiB
- Password is prompted securely (twice)
- Output is written atomically with durability guarantees

### `xor` — High-Reliability Streaming XOR

Perform bitwise XOR between an input file and a key file with strong safety guarantees.


stardust9 xor <input_file> <key_file> <output_file> [--verify]


**Example:**


stardust9 xor secret.txt mykey.bin secret.xored --verify


**Safety features:**
- Writes to a temporary file first
- Atomic commit using `renameat2`
- Full `fsync()` durability
- Optional `--verify` mode performs a full round-trip re-XOR and byte-for-byte comparison before committing

## Design Philosophy

This tool prioritizes **correctness and data durability** over features or raw speed. Both `keygen` and `xor` are designed to be as safe as reasonably possible against crashes and power loss.

Running `stardust9` with no arguments produces no output (clean exit).

## Requirements

- Linux (uses `renameat2` syscall, available since kernel 3.15)
- Rust 1.80+ (tested on 1.96)

## License

MIT OR Apache-2.0
