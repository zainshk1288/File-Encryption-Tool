"""
tests/test_encryptor.py — Test suite for the File Encryption Tool

Covers:
  - Basic encrypt/decrypt round-trip
  - Wrong password detection
  - File tamper detection (GCM auth tag)
  - Multiple file types
  - Empty file edge case
  - Large file handling
  - Argon2 (if available)
  - Header inspection
  - Unique salt/nonce per encryption
  - Output format validation
"""

import os
import struct
import pytest
import tempfile

from encryptor import (
    encrypt_file,
    decrypt_file,
    inspect_file,
    WrongPasswordError,
    UnsupportedFileError,
    MAGIC,
    HEADER_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    KDF_PBKDF2,
    KDF_ARGON2,
    ARGON2_AVAILABLE,
)

PASSWORD = "TestPassword@2024"
WRONG_PW = "WrongPassword@9999"


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def tmp(tmp_path):
    """Provide a temporary directory for each test."""
    return tmp_path


def make_file(path, content: bytes):
    with open(path, "wb") as f:
        f.write(content)
    return str(path)


# ── 1. Basic round-trip ───────────────────────────────────────────

def test_encrypt_decrypt_text(tmp):
    """Encrypt then decrypt plain text — output must match input exactly."""
    plaintext = b"Hello, this is a secret message for InfoSec course!"
    src = make_file(tmp / "plain.txt", plaintext)
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "recovered.txt")

    encrypt_file(src, enc, PASSWORD)
    decrypt_file(enc, dec, PASSWORD)

    with open(dec, "rb") as f:
        assert f.read() == plaintext


def test_encrypt_decrypt_binary(tmp):
    """Encrypt then decrypt binary data."""
    data = bytes(range(256)) * 100
    src  = make_file(tmp / "binary.bin", data)
    enc  = str(tmp / "enc.fenc")
    dec  = str(tmp / "recovered.bin")

    encrypt_file(src, enc, PASSWORD)
    decrypt_file(enc, dec, PASSWORD)

    with open(dec, "rb") as f:
        assert f.read() == data


def test_encrypt_decrypt_pdf_like(tmp):
    """Simulate a PDF file (starts with %PDF header)."""
    fake_pdf = b"%PDF-1.4\n" + os.urandom(4096)
    src = make_file(tmp / "doc.pdf", fake_pdf)
    enc = str(tmp / "doc.fenc")
    dec = str(tmp / "doc_dec.pdf")

    encrypt_file(src, enc, PASSWORD)
    decrypt_file(enc, dec, PASSWORD)

    with open(dec, "rb") as f:
        assert f.read() == fake_pdf


def test_empty_file(tmp):
    """Empty files should encrypt and decrypt correctly."""
    src = make_file(tmp / "empty.txt", b"")
    enc = str(tmp / "empty.fenc")
    dec = str(tmp / "empty_dec.txt")

    encrypt_file(src, enc, PASSWORD)
    decrypt_file(enc, dec, PASSWORD)

    with open(dec, "rb") as f:
        assert f.read() == b""


def test_large_file(tmp):
    """Encrypt a 5 MB random file without errors."""
    data = os.urandom(5 * 1024 * 1024)
    src  = make_file(tmp / "big.bin", data)
    enc  = str(tmp / "big.fenc")
    dec  = str(tmp / "big_dec.bin")

    encrypt_file(src, enc, PASSWORD)
    decrypt_file(enc, dec, PASSWORD)

    with open(dec, "rb") as f:
        assert f.read() == data


# ── 2. Wrong password ─────────────────────────────────────────────

def test_wrong_password_raises(tmp):
    """Wrong password must raise WrongPasswordError — never produce garbage output."""
    src = make_file(tmp / "plain.txt", b"Top secret data")
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "bad.txt")

    encrypt_file(src, enc, PASSWORD)

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, dec, WRONG_PW)


def test_wrong_password_no_output(tmp):
    """When decryption fails, NO output file must be created."""
    src = make_file(tmp / "plain.txt", b"secret")
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "should_not_exist.txt")

    encrypt_file(src, enc, PASSWORD)

    try:
        decrypt_file(enc, dec, WRONG_PW)
    except WrongPasswordError:
        pass

    assert not os.path.exists(dec), "Output file should not exist after failed decryption"


def test_empty_password(tmp):
    """Empty string password should still work as a valid (weak) password."""
    src = make_file(tmp / "plain.txt", b"data")
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "dec.txt")

    encrypt_file(src, enc, "")
    decrypt_file(enc, dec, "")

    with open(dec, "rb") as f:
        assert f.read() == b"data"


def test_empty_password_wrong_rejects(tmp):
    """Decrypting with non-empty password when encrypted with empty must fail."""
    src = make_file(tmp / "plain.txt", b"data")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, "")
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, str(tmp / "dec.txt"), "notblank")


# ── 3. Tamper detection ───────────────────────────────────────────

def test_tamper_ciphertext_detected(tmp):
    """
    Flip a single bit in the ciphertext.
    AES-GCM authentication tag must catch this and raise WrongPasswordError.
    This is the key security property of authenticated encryption.
    """
    src = make_file(tmp / "plain.txt", b"Sensitive file contents here.")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)

    # Flip one byte in the middle of the ciphertext
    with open(enc, "r+b") as f:
        f.seek(HEADER_SIZE + 10)
        original = f.read(1)
        f.seek(HEADER_SIZE + 10)
        f.write(bytes([original[0] ^ 0xFF]))  # flip all bits

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, str(tmp / "dec.txt"), PASSWORD)


def test_tamper_header_detected(tmp):
    """Modifying the salt in the header causes key re-derivation to produce a different key."""
    src = make_file(tmp / "plain.txt", b"Important data")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)

    # Corrupt the salt (bytes 5..20)
    with open(enc, "r+b") as f:
        f.seek(5)
        f.write(os.urandom(SALT_SIZE))

    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, str(tmp / "dec.txt"), PASSWORD)


def test_truncated_file_rejected(tmp):
    """A truncated file must be rejected gracefully."""
    src = make_file(tmp / "plain.txt", b"data")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)

    # Truncate to just the header (no ciphertext)
    with open(enc, "r+b") as f:
        f.truncate(HEADER_SIZE)

    with pytest.raises((WrongPasswordError, UnsupportedFileError)):
        decrypt_file(enc, str(tmp / "dec.txt"), PASSWORD)


# ── 4. Output format ─────────────────────────────────────────────

def test_magic_bytes(tmp):
    """Encrypted file must start with FENC magic bytes."""
    src = make_file(tmp / "plain.txt", b"test")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)

    with open(enc, "rb") as f:
        assert f.read(4) == MAGIC


def test_kdf_id_pbkdf2(tmp):
    """KDF ID byte must be 0x01 for PBKDF2."""
    src = make_file(tmp / "plain.txt", b"test")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD, use_argon2=False)

    with open(enc, "rb") as f:
        data = f.read(5)
    assert data[4] == KDF_PBKDF2


def test_output_size(tmp):
    """Encrypted file size = HEADER_SIZE + len(plaintext) + 16 (GCM tag)."""
    plaintext = b"x" * 1000
    src = make_file(tmp / "plain.txt", plaintext)
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)

    expected = HEADER_SIZE + len(plaintext) + 16
    assert os.path.getsize(enc) == expected


def test_ciphertext_differs_from_plaintext(tmp):
    """The ciphertext portion must not equal the plaintext."""
    plaintext = b"Hello World" * 100
    src = make_file(tmp / "plain.txt", plaintext)
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)

    with open(enc, "rb") as f:
        cipher_bytes = f.read()[HEADER_SIZE:]

    assert cipher_bytes != plaintext


# ── 5. Randomness properties ──────────────────────────────────────

def test_unique_salt_per_encryption(tmp):
    """
    Encrypting the same file twice must produce different salts.
    This ensures even identical passwords produce different keys per file.
    """
    src = make_file(tmp / "plain.txt", b"same content")
    enc1 = str(tmp / "enc1.fenc")
    enc2 = str(tmp / "enc2.fenc")

    encrypt_file(src, enc1, PASSWORD)
    encrypt_file(src, enc2, PASSWORD)

    with open(enc1, "rb") as f: salt1 = f.read(5 + SALT_SIZE)[5:]
    with open(enc2, "rb") as f: salt2 = f.read(5 + SALT_SIZE)[5:]

    assert salt1 != salt2, "Salt must be unique per encryption"


def test_unique_nonce_per_encryption(tmp):
    """Nonce must be different every time — nonce reuse in GCM is catastrophic."""
    src = make_file(tmp / "plain.txt", b"same content")
    enc1 = str(tmp / "enc1.fenc")
    enc2 = str(tmp / "enc2.fenc")

    encrypt_file(src, enc1, PASSWORD)
    encrypt_file(src, enc2, PASSWORD)

    nonce_start = 5 + SALT_SIZE
    with open(enc1, "rb") as f: n1 = f.read(nonce_start + NONCE_SIZE)[nonce_start:]
    with open(enc2, "rb") as f: n2 = f.read(nonce_start + NONCE_SIZE)[nonce_start:]

    assert n1 != n2, "Nonce must be unique per encryption"


def test_unique_ciphertext_same_plaintext(tmp):
    """Same plaintext + same password → different ciphertext (due to random nonce)."""
    plaintext = b"Identical content"
    src = make_file(tmp / "plain.txt", plaintext)
    enc1 = str(tmp / "enc1.fenc")
    enc2 = str(tmp / "enc2.fenc")

    encrypt_file(src, enc1, PASSWORD)
    encrypt_file(src, enc2, PASSWORD)

    with open(enc1, "rb") as f: c1 = f.read()[HEADER_SIZE:]
    with open(enc2, "rb") as f: c2 = f.read()[HEADER_SIZE:]

    assert c1 != c2, "Same plaintext must produce different ciphertext due to random nonce"


# ── 6. Inspect ───────────────────────────────────────────────────

def test_inspect_valid_file(tmp):
    """inspect_file should return correct metadata."""
    src = make_file(tmp / "plain.txt", b"test data")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD)
    info = inspect_file(enc)

    assert info["magic"] == "FENC"
    assert info["kdf"] == "PBKDF2"
    assert isinstance(info["iterations"], int)


def test_inspect_invalid_file(tmp):
    """inspect_file on a non-FENC file should raise UnsupportedFileError."""
    random_file = make_file(tmp / "random.bin", os.urandom(100))
    with pytest.raises(UnsupportedFileError):
        inspect_file(random_file)


# ── 7. Argon2 ────────────────────────────────────────────────────

@pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
def test_argon2_round_trip(tmp):
    """Argon2id encrypt/decrypt round-trip must work correctly."""
    plaintext = b"Argon2 protected secret"
    src = make_file(tmp / "plain.txt", plaintext)
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "dec.txt")

    encrypt_file(src, enc, PASSWORD, use_argon2=True)
    decrypt_file(enc, dec, PASSWORD)

    with open(dec, "rb") as f:
        assert f.read() == plaintext


@pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
def test_argon2_kdf_id(tmp):
    """KDF ID byte must be 0x02 for Argon2."""
    src = make_file(tmp / "plain.txt", b"test")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD, use_argon2=True)

    with open(enc, "rb") as f:
        data = f.read(5)
    assert data[4] == KDF_ARGON2


@pytest.mark.skipif(not ARGON2_AVAILABLE, reason="argon2-cffi not installed")
def test_argon2_wrong_password(tmp):
    """Wrong password with Argon2 must still raise WrongPasswordError."""
    src = make_file(tmp / "plain.txt", b"secret")
    enc = str(tmp / "enc.fenc")

    encrypt_file(src, enc, PASSWORD, use_argon2=True)
    with pytest.raises(WrongPasswordError):
        decrypt_file(enc, str(tmp / "dec.txt"), WRONG_PW)


# ── 8. Special characters ─────────────────────────────────────────

def test_unicode_password(tmp):
    """Non-ASCII password characters must work correctly."""
    password = "P@$$w0rd_اردو_123"
    src = make_file(tmp / "plain.txt", b"unicode password test")
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "dec.txt")

    encrypt_file(src, enc, password)
    decrypt_file(enc, dec, password)

    with open(dec, "rb") as f:
        assert f.read() == b"unicode password test"


def test_very_long_password(tmp):
    """A 512-character password should work fine."""
    password = "A" * 512
    src = make_file(tmp / "plain.txt", b"long password test")
    enc = str(tmp / "enc.fenc")
    dec = str(tmp / "dec.txt")

    encrypt_file(src, enc, password)
    decrypt_file(enc, dec, password)

    with open(dec, "rb") as f:
        assert f.read() == b"long password test"
