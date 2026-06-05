# tools

**Deterministic key generation + maximum-reliability streaming XOR**  
A single-file Linux CLI tool for secure, reproducible encryption using a password-derived keystream.

## What is this?

`tools` provides two commands:

- `keygen` — Generate a large, deterministic keystream from a password + optional context.
- `xor` — Perform high-reliability **in-place** XOR using that keystream.

It is designed for **maximum reliability**:
- Atomic file replacement (never leaves partial files)
- Full verification before committing changes
- Durability guarantees (`fsync` + directory sync)
- Works safely even on very large files (up to 20 GiB)

**Important**: This is **not** a true one-time pad. The keystream is deterministically derived from your password using Argon2id + ChaCha20. It is suitable for informal/personal encryption where you want reproducible keys, but it is **not** information-theoretically secure like a real OTP.

## Building

Requires a recent Rust toolchain (edition 2024 / Rust 1.85+ recommended).

```bash
git clone <your-repo>
cd tools
cargo build --release
```

The resulting binary is `target/release/tools`.

> **Note**: This tool is **Linux-only**. It uses `renameat2(RENAME_NOREPLACE)` for atomic file replacement. It will not compile on Windows or macOS.

## Usage

### 1. Generate a key (`keygen`)

```bash
tools keygen <size-in-bytes> [--context <name>]
```

**Examples:**

```bash
# Generate a 1 GiB key
tools keygen 1073741824

# Generate a 5 GiB key with a context (useful for different purposes)
tools keygen 5368709120 --context backup-2026

# Generate a small test key
tools keygen 1048576 --context test
```

**What it does:**
- Prompts for a password (twice for confirmation)
- Derives a master key using **Argon2id** (128 MiB memory, 3 iterations, 4 lanes)
- Uses domain separation to create a ChaCha20 keystream
- Writes the keystream to `key.key` **next to the `tools` binary**
- Silently overwrites `key.key` if it already exists (atomic replace)

The key is **deterministic**: the same password + context will always produce the exact same `key.key`.

### 2. XOR a file in place (`xor`)

```bash
tools xor <file>
```

This is the main encryption/decryption command.

**Example:**

```bash
# Encrypt a file (in place)
tools xor secret-document.pdf

# The file is now encrypted. To decrypt it, just run the same command again:
tools xor secret-document.pdf
```

**What it does:**
- Reads `key.key` (must exist next to the binary)
- XORs the target file with the keystream **in streaming fashion**
- Writes to a temporary file first
- **Always verifies** the result by re-XORing it with the key and comparing it to the original
- Only if verification passes does it **atomically replace** the original file
- If anything fails, the original file is left completely untouched

**Key safety features:**
- Never modifies the original until verification succeeds
- Uses atomic `renameat2` so the file is either fully old or fully new
- Full `fsync` + directory sync for durability
- Explicitly refuses to operate on `key.key` itself

## Command Summary

| Command                  | Description                                      | Example                          |
|--------------------------|--------------------------------------------------|----------------------------------|
| `tools keygen <size>`    | Generate `key.key` from password                 | `tools keygen 1073741824`        |
| `tools keygen <size> --context <name>` | Generate key with specific context     | `tools keygen 1G --context work` |
| `tools xor <file>`       | Encrypt/decrypt file **in place** (always verifies) | `tools xor myfile.bin`        |

## How It Works (Technical Overview)

1. **Key Generation**
   - Password + context → Argon2id → 32-byte master key
   - Domain separation:
     - `stream_key = SHA256(master_key || "stream")`
     - `nonce = first 12 bytes of SHA256(master_key || "nonce")`
   - ChaCha20 keystream is generated from the above

2. **XOR Operation**
   - Streams data in 1 MiB chunks
   - XORs input with keystream on the fly
   - Writes to `.tmp.<pid>` file
   - Verifies by reading original + key + temp and checking round-trip
   - Atomic replace using `renameat2(RENAME_NOREPLACE)`

## Safety & Durability Guarantees

- **Atomicity**: Files are replaced atomically. You will never see a partially written file.
- **Verification**: `xor` always verifies before committing (full re-XOR + byte comparison).
- **Durability**: `fsync()` on data file + `fsync()` on parent directory.
- **Crash safety**: Power loss or crash during operation leaves the original file intact.
- **Memory safety**: Password and master key are wiped from memory after use.
- **Self-protection**: Refuses to XOR `key.key` with itself.

## Limitations & Recommendations

- **Key location**: `key.key` must live next to the `tools` binary. This makes the tool portable but means you should keep the binary + key together.
- **Deterministic keys**: Same password + context = same key. This is intentional but means you must remember (or write down) the context you used.
- **Not a true OTP**: This provides strong practical security for most personal use cases, but it is **not** information-theoretically secure.
- **Backup your key**: If you lose `key.key` (or forget the password/context), your encrypted files are unrecoverable.
- **Large files**: Works fine up to 20 GiB. Requires temporary disk space equal to the file size during `xor`.

## Philosophy

This tool prioritizes **reliability and simplicity** over features. The commands are intentionally minimal:

- `keygen` just makes a key
- `xor` just transforms a file in place (safely)

No config files, no key management UI, no multiple keys — just a robust, deterministic keystream you control with a password.

---

**Linux only** • Built with safety and durability as first-class concerns.