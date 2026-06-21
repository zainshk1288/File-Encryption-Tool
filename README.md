# File Encryption Tool
### AES-256-GCM · PBKDF2 / Argon2 · Authenticated Encryption

A command-line file encryption tool built for the Information Security course project.  
Encrypts and decrypts any file type using **AES-256-GCM** with **password-based key derivation**.

---

## Features

- **AES-256-GCM** — authenticated encryption (confidentiality + integrity in one step)
- **PBKDF2-HMAC-SHA256** — 200,000 iteration key derivation (default)
- **Argon2id** — memory-hard alternative KDF resistant to GPU cracking
- **Random salt + nonce** per file — same password never produces the same ciphertext
- **Zero password storage** — password is never written anywhere
- **Tamper detection** — GCM auth tag rejects any modified file before decryption
- **Benchmark mode** — measures encryption speed across file sizes
- **28 automated tests** covering security properties, edge cases, and attack scenarios

---

## Installation

```bash
# Clone or unzip the project
cd file_encryptor

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Encrypt a file
```bash
python cli.py encrypt secret.pdf secret.enc
```

### Encrypt with Argon2 (stronger, slower)
```bash
python cli.py encrypt secret.pdf secret.enc --kdf argon2
```

### Decrypt a file
```bash
python cli.py decrypt secret.enc recovered.pdf
```

### Inspect an encrypted file (no password needed)
```bash
python cli.py inspect secret.enc
```

### Run performance benchmark
```bash
python cli.py benchmark
```

---

## Encrypted File Format

```
┌──────────┬──────────┬────────────┬─────────────┬──────────────┬───────────────────────────┐
│ Magic    │ KDF ID   │ Salt       │ Nonce       │ Iterations   │ Ciphertext + GCM Tag      │
│ 4 bytes  │ 1 byte   │ 16 bytes   │ 12 bytes    │ 4 bytes      │ N + 16 bytes              │
│ "FENC"   │ 01/02    │ random     │ random      │ big-endian   │ AES-256-GCM output        │
└──────────┴──────────┴────────────┴─────────────┴──────────────┴───────────────────────────┘
Total header: 37 bytes   |   Total overhead: 53 bytes (header + GCM tag)
```

**Nothing in this file can decrypt the data without the correct password.**  
The salt and nonce are not secret — they are random values needed to reproduce the key and cipher state.

---

## How It Works

### Step 1 — Password → Key (PBKDF2)

```
password + random_salt  →  PBKDF2(HMAC-SHA256, 200,000 rounds)  →  256-bit key
```

Why not use the password directly? Passwords have low entropy. A KDF applies the hash
function 200,000 times, making each brute-force guess 200,000× slower.

### Step 2 — Key + File → Ciphertext (AES-256-GCM)

```
key + random_nonce + plaintext  →  AES-256-GCM  →  ciphertext + auth_tag
```

GCM mode provides **authenticated encryption**:
- The auth tag cryptographically covers every byte of ciphertext
- Any modification (wrong password, bit flip, truncation) → decryption immediately fails
- No partial or garbage output is ever written to disk

### Step 3 — Decryption

```
stored_salt + password  →  same key  →  AES-256-GCM.decrypt(nonce, ciphertext)
                                         │
                                         ├── auth tag OK  → write plaintext
                                         └── auth tag BAD → raise WrongPasswordError
```

---

## Security Analysis

### Why AES-256?
AES-256 has a 2²⁵⁶ key space. Even under Grover's quantum algorithm, the effective
security reduces to 2¹²⁸ — still completely infeasible to brute-force.

### Why GCM mode over CBC?
CBC requires a separate HMAC for integrity and is vulnerable to padding oracle attacks.
GCM provides both confidentiality and integrity natively with no additional overhead.

### Why PBKDF2 with 200,000 iterations?
NIST SP 800-132 recommends ≥ 100,000 iterations for SHA-256.  
At 200,000 iterations, a GPU capable of 10 billion SHA-256/sec can only test ~50,000 passwords/sec.

### Why Argon2?
Argon2id uses 64 MB of memory per derivation attempt, making GPU/ASIC attacks impractical
because memory bandwidth is the bottleneck, not compute.

### Nonce / IV Management
A fresh 12-byte random nonce is generated for every encryption call. Nonce reuse with the
same key in GCM would be catastrophic (key stream XOR reveals plaintext). The random
generation approach eliminates this risk for any realistic workload.

### What if the user forgets their password?
The file is permanently unrecoverable. There is no backdoor, no recovery key.
This is the security guarantee — not a limitation.

---

## Running Tests

```bash
# From the file_encryptor/ directory
pytest tests/ -v
```

### Test coverage includes:
- Round-trip correctness (text, binary, PDF-like, empty, 5 MB)
- Wrong password rejection (raises WrongPasswordError, no output written)
- Tamper detection (single bit flip in ciphertext → rejected)
- Header corruption detection
- Output format validation (magic bytes, KDF ID, file size)
- Unique salt and nonce per encryption
- Unicode and very long passwords
- Argon2 round-trip (if installed)

---

## Project Structure

```
file_encryptor/
├── encryptor.py        Core cryptographic logic (KDF, encrypt, decrypt, inspect)
├── cli.py              Command-line interface with coloured output and benchmark mode
├── requirements.txt    Python dependencies
├── README.md           This file
└── tests/
    └── test_encryptor.py   28 automated tests
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | AES-256-GCM cipher, PBKDF2-HMAC-SHA256 |
| `argon2-cffi` | Argon2id key derivation |
| `pytest` | Test runner |

All dependencies are well-maintained, production-grade cryptographic libraries.
No custom cipher implementations — rolling your own crypto is a security anti-pattern.

---

*Information Security Course Project*
