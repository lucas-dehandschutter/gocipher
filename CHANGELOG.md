# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-13

### Breaking Changes
- **Incompatibility**: Files encrypted with version `0.2.0` **cannot be decrypted** with this version (`0.3.0`) — the format version was bumped to `0x03` because the AAD layout changed (see Security below), and unknown versions are rejected explicitly.
- **CLI redesign**: The `-d/--decrypt` flag and the `-s/--string` / `-f/--file` input flags are removed. Operations are now explicit subcommands (`gocipher encrypt` / `gocipher decrypt`) taking an optional `[file]` positional argument; with no argument, input is read from stdin.

### Added
- `-o/--output` flag on both subcommands to override the default output destination.
- Stdin/stdout I/O modes: piped stdin is treated as the raw data stream; interactive encrypt output is hex-encoded on a terminal and raw when redirected; interactive decrypt prompts for a pasted hex line.
- Security regression tests covering chunk reordering, chunk deletion, header tampering, and oversized inputs.

### Changed
- When stdin carries the data, the password is prompted via the controlling terminal (`/dev/tty`, `CONIN$` on Windows) so data and password never collide; headless pipes without a terminal fail with an error instead of misreading the data as the password.
- Bumped `golang.org/x/crypto` to v0.54.0.

### Security
- **Full-stream authentication**: Each chunk's AES-GCM AAD now covers the entire 32-byte header plus a per-chunk counter (never stored on the wire, recomputed during decryption), making chunk **reordering**, **deletion**, and **header tampering** detectable — previously only tail truncation was caught.
- **Allocation hardening**: Chunk lengths and Argon2id parameters exceeding safe bounds are rejected before allocating, preventing memory-amplification DoS from crafted files.
- **Memory hygiene**: Passwords are handled as `[]byte` and zeroed (along with derived keys) immediately after use.

## [0.2.0] - 2026-06-05

### Breaking Changes
- **Incompatibility**: Files encrypted with version `0.1.0` **cannot be decrypted** with this version (`0.2.0`) due to fundamental changes in the stream format.

### Added
- **Configurable KDF**: Added CLI flags (`-t/--time`, `-m/--memory`, `-p/--threads`) to customize Argon2id key derivation parameters during encryption.

### Changed
- **Encryption Format**: Shifted to a custom versioned chunked streaming format.
  - Chunks are now strictly **64KB** (standard compliance).
  - Explicit **4-byte Length** prefix for robust parsing.
  - Partial blocks (< 64KB) are immediately marked as **Terminal** (Flag 1), avoiding empty chunks in most cases.
- **Key Derivation**: Migrated from **PBKDF2** to **Argon2id** (3 iterations, 64MB memory, 4 threads by default) to resist GPU/ASIC brute-force attacks.

### Security
- **Versioned Header**: Added a 32-byte padded file header starting with magic bytes `GOC` and format version `0x02`, embedding the Argon2id KDF parameters (time, memory, threads), 3 reserved bytes for alignment/future use, and the random salt.
- **Full AAD Protection**: The Chunk Flag and Length are now authenticated (AAD) by AES-GCM tags. Any tampering with the block structure or size will cause immediate decryption failure.

## [0.1.0] - 2025-12-10

### Added
- Initial release of GoCipher.
- Core encryption engine using **AES-256-GCM**.
- Secure key derivation using **PBKDF2** (SHA-256, 100,000 iterations, random salt).
- CLI implementation with Cobra.
- Support for encrypting/decrypting raw strings via `-s` flag.
- Support for encrypting/decrypting files via `-f` flag.
- Hex encoding for ciphertext output to ensure safe handling.
- Project structuration following standard Go layout.
