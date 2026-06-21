"""
encryptor.py — Core cryptographic logic for the File Encryption Tool

Encryption scheme:
  - Key Derivation : PBKDF2-HMAC-SHA256  (default) or Argon2id
  - Cipher         : AES-256-GCM  (authenticated encryption)
  - Output format  : [magic(4)] [kdf_id(1)] [salt(16)] [nonce(12)]
                     [iterations(4, big-endian)] [ciphertext+GCM-tag(n+16)]

The password is NEVER stored. The same password + stored salt will always
re-derive the exact same 256-bit key, making decryption possible without
ever saving the key or password anywhere.
"""

import os
import struct
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────
MAGIC           = b"FENC"   # file header magic bytes
KDF_PBKDF2      = 0x01
KDF_ARGON2      = 0x02
SALT_SIZE       = 16        # bytes
NONCE_SIZE      = 12        # bytes (96-bit, recommended for GCM)
KEY_SIZE        = 32        # bytes (256-bit key for AES-256)
PBKDF2_ITERS    = 200_000   # NIST recommends ≥ 100k for SHA-256
ARGON2_TIME     = 3         # time cost (iterations)
ARGON2_MEM      = 65536     # memory cost in KB (64 MB)
ARGON2_PARALLEL = 4         # parallelism factor
HEADER_SIZE     = 4 + 1 + SALT_SIZE + NONCE_SIZE + 4   # 37 bytes


class WrongPasswordError(Exception):
    """Raised when decryption fails due to wrong password or tampered file."""
    pass


class UnsupportedFileError(Exception):
    """Raised when the file is not a valid FENC encrypted file."""
    pass


# ── Key Derivation ────────────────────────────────────────────────

def derive_key_pbkdf2(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    """
    PBKDF2-HMAC-SHA256: applies the hash function `iterations` times.
    Each brute-force guess costs `iterations` SHA-256 operations.
    With 200,000 iterations, a GPU doing 1B guesses/sec slows to ~5,000/sec.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """
    Argon2id: memory-hard KDF. Requires ARGON2_MEM KB of RAM per attempt,
    making GPU/ASIC brute-force attacks far more expensive than PBKDF2.
    Winner of the 2015 Password Hashing Competition.
    """
    if not ARGON2_AVAILABLE:
        raise RuntimeError(
            "argon2-cffi is not installed. Run: pip install argon2-cffi"
        )
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEM,
        parallelism=ARGON2_PARALLEL,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def derive_key(password: str, salt: bytes, kdf: int, iterations: int = PBKDF2_ITERS) -> bytes:
    """Dispatch to the correct KDF based on the kdf identifier."""
    if kdf == KDF_PBKDF2:
        return derive_key_pbkdf2(password, salt, iterations)
    elif kdf == KDF_ARGON2:
        return derive_key_argon2(password, salt)
    else:
        raise ValueError(f"Unknown KDF identifier: {kdf}")


# ── Encryption ────────────────────────────────────────────────────

def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    use_argon2: bool = False,
    iterations: int = PBKDF2_ITERS,
) -> dict:
    """
    Encrypt a file using AES-256-GCM with password-based key derivation.

    Output file format:
      [FENC magic 4B] [kdf_id 1B] [salt 16B] [nonce 12B] [iterations 4B] [ciphertext]

    The GCM authentication tag (16 bytes) is automatically appended to
    ciphertext by the cryptography library.

    Returns a dict with timing and size info for benchmarking.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    kdf_id = KDF_ARGON2 if (use_argon2 and ARGON2_AVAILABLE) else KDF_PBKDF2

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    plaintext_size = len(plaintext)

    # Generate fresh random salt and nonce for every encryption
    # CRITICAL: reusing a nonce with the same key in GCM breaks security entirely
    salt  = os.urandom(SALT_SIZE)   # used for KDF only, stored in file
    nonce = os.urandom(NONCE_SIZE)  # used for AES-GCM, stored in file

    # Derive the 256-bit key (password never stored)
    t_kdf_start = time.perf_counter()
    key = derive_key(password, salt, kdf_id, iterations)
    t_kdf = time.perf_counter() - t_kdf_start

    # Encrypt with AES-256-GCM
    # GCM automatically appends a 16-byte authentication tag to ciphertext
    t_enc_start = time.perf_counter()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    t_enc = time.perf_counter() - t_enc_start

    # Build header: magic + kdf_id + salt + nonce + iterations
    iters_bytes = struct.pack(">I", iterations)
    header = MAGIC + bytes([kdf_id]) + salt + nonce + iters_bytes

    # Write output file
    with open(output_path, "wb") as f:
        f.write(header + ciphertext)

    return {
        "plaintext_size":  plaintext_size,
        "encrypted_size":  os.path.getsize(output_path),
        "kdf":             "Argon2id" if kdf_id == KDF_ARGON2 else "PBKDF2",
        "iterations":      iterations if kdf_id == KDF_PBKDF2 else None,
        "kdf_time_s":      round(t_kdf, 4),
        "enc_time_s":      round(t_enc, 6),
        "overhead_bytes":  HEADER_SIZE + 16,  # header + GCM tag
    }


# ── Decryption ────────────────────────────────────────────────────

def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Decrypt a FENC-encrypted file.

    1. Read and validate the magic header.
    2. Extract salt, nonce, kdf_id, iterations from the header.
    3. Re-derive the key using the stored salt + user's password.
    4. AES-256-GCM decryption — raises InvalidTag if:
       - Password is wrong (key mismatch → tag fails)
       - File has been tampered with (any bit flip → tag fails)
    5. Write plaintext ONLY if authentication succeeds.

    Returns timing info dict.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path, "rb") as f:
        data = f.read()

    # Validate magic bytes
    if len(data) < HEADER_SIZE + 16:
        raise UnsupportedFileError("File is too small to be a valid FENC file.")
    if data[:4] != MAGIC:
        raise UnsupportedFileError(
            "File does not appear to be a FENC encrypted file (bad magic bytes)."
        )

    # Parse header
    kdf_id     = data[4]
    salt       = data[5:21]
    nonce      = data[21:33]
    iterations = struct.unpack(">I", data[33:37])[0]
    ciphertext = data[37:]   # includes the 16-byte GCM tag at the end

    # Re-derive the same key
    t_kdf_start = time.perf_counter()
    key = derive_key(password, salt, kdf_id, iterations)
    t_kdf = time.perf_counter() - t_kdf_start

    # Decrypt + verify authentication tag in one step
    # If password is wrong OR file was tampered with → InvalidTag exception
    t_dec_start = time.perf_counter()
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise WrongPasswordError(
            "Decryption failed: wrong password or the file has been tampered with."
        )
    t_dec = time.perf_counter() - t_dec_start

    # Write plaintext only after successful authentication
    with open(output_path, "wb") as f:
        f.write(plaintext)

    return {
        "decrypted_size": len(plaintext),
        "kdf":            "Argon2id" if kdf_id == KDF_ARGON2 else "PBKDF2",
        "kdf_time_s":     round(t_kdf, 4),
        "dec_time_s":     round(t_dec, 6),
    }


# ── File Info ─────────────────────────────────────────────────────

def inspect_file(path: str) -> dict:
    """Read and return the header metadata of a FENC encrypted file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        data = f.read(HEADER_SIZE)

    if len(data) < HEADER_SIZE or data[:4] != MAGIC:
        raise UnsupportedFileError("Not a valid FENC encrypted file.")

    kdf_id     = data[4]
    iterations = struct.unpack(">I", data[33:37])[0]

    return {
        "magic":          data[:4].decode(),
        "kdf":            "Argon2id" if kdf_id == KDF_ARGON2 else "PBKDF2",
        "iterations":     iterations if kdf_id == KDF_PBKDF2 else "N/A (Argon2)",
        "file_size":      os.path.getsize(path),
        "ciphertext_size": os.path.getsize(path) - HEADER_SIZE,
    }
