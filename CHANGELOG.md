# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
