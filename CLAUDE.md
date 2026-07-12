# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go build -o gocipher              # build the binary
go run main.go encrypt [file]     # run without building (or decrypt; no file arg reads stdin)
go test ./...                     # run all tests
go test -v ./...                  # run all tests, verbose (what CI runs)
go test ./pkg/crypto -run TestName # run a single test
go vet ./...                      # static checks
```

There is no linter configured beyond `go vet`. CI (`.github/workflows/ci.yml`) runs only `go test -v ./...` on push/PR to `main`. Releases are built via GoReleaser (`.goreleaser.yml`) and triggered by pushing a `v*` tag (`.github/workflows/release.yml`), producing linux/windows/darwin amd64/arm64 archives.

## Architecture

GoCipher is a Cobra-based CLI with an `encrypt` and a `decrypt` subcommand (`gocipher encrypt`/`gocipher decrypt`), plus two packages:

- `cmd/root.go` — bare parent command, just registers the two subcommands.
- `cmd/encrypt.go` / `cmd/decrypt.go` — each subcommand's flags and `Run`. Both take an optional `[file]` positional arg (`cobra.MaximumNArgs(1)`) and a shared `-o/--output`. `encrypt` additionally exposes `-t/-m/-p` (Argon2id params); `decrypt` does not, since those are read back from the ciphertext header.
- `cmd/common.go` — logic shared by both subcommands: `resolveInput` (file arg or stdin), `prepareDecryptInput` (hex-decodes a pasted line when decrypt's stdin is an interactive terminal), `resolveOutput` (file arg or `-o` or stdout, with `.enc`/`.dec` naming), `readPassword`/`promptPassword`/`openTTY` (see Password handling below).

Each subcommand binds its own package-level flag variables (e.g. `encryptOutputPath` vs. `decryptOutputPath`) — Cobra subcommands need distinct bound variables even for same-named flags, so don't try to share a single var across both.

### Encrypted stream format

Encryption is chunked streaming, not whole-buffer, so arbitrarily large files can be processed with bounded memory. `EncryptStream`/`DecryptStream` in `crypto.go` are the core; `Encrypt`/`Decrypt` are convenience wrappers over `[]byte` that pipe through the same streaming functions via `io.Pipe`.

Wire format (currently version `0x03`):
1. **32-byte header**: magic `"GOC"` (3B) + version (1B) + Argon2id params — Time (4B), Memory (4B), Threads (1B) — + 3B reserved + 16B salt. The Argon2id parameters are stored in the header (not hardcoded), so encryption can use custom `-t/-m/-p` values and decryption reads them back automatically.
2. **Repeated chunks**: each is written as Flag (1B) + Length (4B) + Nonce (12B) + AES-GCM ciphertext. Flag `0` = more data follows, Flag `1` = terminal chunk (ends the stream, even if empty — a file whose size is an exact multiple of `chunkSize` gets an explicit empty terminal chunk appended, see the edge-case return at the end of `EncryptStream`). Chunk size is 64KB (`chunkSize`).
3. **AAD is larger than what's on the wire**: each chunk's GCM tag authenticates `header (32B) + flag (1B) + length (4B) + counter (8B)` = `aadSize` (45B), laid out at the `aad*Off` offsets. Only flag+length are written to the stream; the header is written once up front, and the `counter` (a per-chunk sequence number) is **never stored** — the decryptor recomputes it by counting chunks. This is what makes chunk **reordering** and **deletion** detectable (a shifted/misordered chunk gets a counter mismatch → `gcm.Open` fails), and authenticates the header itself (tampering with version/params/reserved bytes → auth failure). Tail truncation is caught separately by the missing terminal chunk.
4. `DecryptStream` rejects any chunk whose `Length` exceeds `chunkSize` before allocating, so a crafted length can't force a huge allocation.
5. Key is derived per-operation via `argon2.IDKey(password, salt, ...)` from the header's salt + params, then zeroed (`ZeroMemory`) immediately after `aes.NewCipher` consumes it.

When modifying the wire format or the AAD layout, bump `headerVersion` — `DecryptStream` rejects unknown versions explicitly (hard error, no backward-compat parsing path), so a bump makes old and new files mutually unreadable by design.

### Password handling

Passwords are `[]byte` throughout (not `string`), specifically so `ZeroMemory` can wipe them from memory after use — `readPassword` in `cmd/common.go` returns a cleanup func that every caller pairs with `defer`. Preserve this pattern for any new password-derived buffers.

There is no flag to pass a password directly (by design — avoids it leaking via shell history/`ps`). `readPassword(confirm, stdinIsData bool)` has to pick where to read from without colliding with data:
- If input is a file (`stdinIsData == false`): behaves like a plain CLI — masked prompt via `term.ReadPassword` on stdin's fd when stdin is a terminal, or a raw line read from stdin when piped (supports `echo "$PASS" | gocipher decrypt file.enc`).
- If input is stdin itself (`stdinIsData == true`, no file arg — see CLI I/O modes below): stdin is already claimed as the data stream, so the password is always prompted for via `openTTY()` (`/dev/tty`, or `CONIN$` on Windows), never via stdin. If no controlling terminal is available in that case (e.g. a fully headless script piping data with no tty), `readPassword` returns an error rather than silently reading the piped data as the password.

### CLI I/O modes

Both subcommands take an optional `[file]` positional arg; no file means stdin is the input (`resolveInput`, `cmd/common.go`) — there's no separate "string mode" flag anymore, stdin *is* the string-input path (`echo -n "text" | gocipher encrypt`, or type + Ctrl+D interactively).

- File input: output defaults to `<file>.enc` when encrypting, or a trailing `.enc` stripped when decrypting (falls back to `<file>.dec` if there's no `.enc` suffix). Always raw binary, never hex.
- Stdin input, encrypt: output goes to stdout by default; hex-encoded (`hex.NewEncoder`) if stdout is an interactive terminal, raw bytes otherwise (redirected/piped) — decided by `term.IsTerminal(syscall.Stdout)` in `cmd/encrypt.go`.
- Stdin input, decrypt: `prepareDecryptInput` checks stdin itself — if it's an interactive terminal, prompts for and hex-decodes a single pasted line; if piped, treats stdin as the raw encrypted stream directly (streams large piped files fine, same as file input).
- `-o/--output` always overrides the default destination, for either input source.
