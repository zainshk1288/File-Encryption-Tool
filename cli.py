"""
cli.py — Command-Line Interface for the File Encryption Tool

Usage examples:
  python cli.py encrypt secret.pdf secret.enc
  python cli.py decrypt secret.enc recovered.pdf
  python cli.py inspect secret.enc
  python cli.py benchmark
  python cli.py encrypt report.docx report.enc --kdf argon2
"""

import argparse
import getpass
import os
import sys

from encryptor import (
    encrypt_file,
    decrypt_file,
    inspect_file,
    WrongPasswordError,
    UnsupportedFileError,
    PBKDF2_ITERS,
    ARGON2_AVAILABLE,
)


# ── Colour helpers (Windows-safe) ──────────────────────────────────
def _c(code, text):
    """Wrap text in ANSI colour if the terminal supports it."""
    if sys.stdout.isatty() and os.name != "nt":
        return f"\033[{code}m{text}\033[0m"
    return text

def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def cyan(t):   return _c("96", t)
def yellow(t): return _c("93", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)


def print_banner():
    print(cyan(r"""
  ███████╗███╗   ██╗ ██████╗
  ██╔════╝████╗  ██║██╔════╝
  █████╗  ██╔██╗ ██║██║
  ██╔══╝  ██║╚██╗██║██║
  ██║     ██║ ╚████║╚██████╗
  ╚═╝     ╚═╝  ╚═══╝ ╚═════╝   File Encryption Tool
"""))
    print(dim("  AES-256-GCM  ·  PBKDF2 / Argon2  ·  Authenticated Encryption\n"))


def human_size(n: int) -> str:
    """Convert bytes to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ── Subcommand handlers ────────────────────────────────────────────

def cmd_encrypt(args):
    """Handle the 'encrypt' subcommand."""
    if not os.path.isfile(args.input):
        print(red(f"  ✗  Input file not found: {args.input}"))
        sys.exit(1)

    # Prompt for password (hidden input, confirmed)
    password = getpass.getpass("  Enter password: ")
    if len(password) < 6:
        print(yellow("  ⚠  Password is very short — consider using a longer one."))
    confirm = getpass.getpass("  Confirm password: ")
    if password != confirm:
        print(red("  ✗  Passwords do not match."))
        sys.exit(1)

    use_argon2 = (args.kdf == "argon2")
    if use_argon2 and not ARGON2_AVAILABLE:
        print(yellow("  ⚠  argon2-cffi not installed. Falling back to PBKDF2."))
        print(dim("      Install with: pip install argon2-cffi"))
        use_argon2 = False

    kdf_label = "Argon2id" if use_argon2 else f"PBKDF2 ({args.iterations:,} iterations)"
    print(f"\n  {dim('KDF       :')} {kdf_label}")
    print(f"  {dim('Cipher    :')} AES-256-GCM")
    print(f"  {dim('Input     :')} {args.input}  ({human_size(os.path.getsize(args.input))})")
    print(f"  {dim('Output    :')} {args.output}")
    print()

    try:
        result = encrypt_file(
            args.input,
            args.output,
            password,
            use_argon2=use_argon2,
            iterations=args.iterations,
        )
    except Exception as e:
        print(red(f"  ✗  Encryption failed: {e}"))
        sys.exit(1)

    print(green("  ✔  File encrypted successfully!\n"))
    print(f"  {dim('KDF time     :')} {result['kdf_time_s']:.3f}s")
    print(f"  {dim('Encrypt time :')} {result['enc_time_s']*1000:.2f}ms")
    print(f"  {dim('Plaintext    :')} {human_size(result['plaintext_size'])}")
    print(f"  {dim('Encrypted    :')} {human_size(result['encrypted_size'])}")
    print(f"  {dim('Overhead     :')} {result['overhead_bytes']} bytes (header + GCM tag)")
    print()


def cmd_decrypt(args):
    """Handle the 'decrypt' subcommand."""
    if not os.path.isfile(args.input):
        print(red(f"  ✗  Input file not found: {args.input}"))
        sys.exit(1)

    # Validate it's a FENC file before asking for password
    try:
        info = inspect_file(args.input)
    except UnsupportedFileError as e:
        print(red(f"  ✗  {e}"))
        sys.exit(1)

    print(f"\n  {dim('KDF       :')} {info['kdf']}")
    print(f"  {dim('Cipher    :')} AES-256-GCM")
    print(f"  {dim('Encrypted :')} {human_size(info['file_size'])}")
    print()

    password = getpass.getpass("  Enter password: ")

    try:
        result = decrypt_file(args.input, args.output, password)
    except WrongPasswordError as e:
        print(red(f"\n  ✗  {e}"))
        sys.exit(1)
    except Exception as e:
        print(red(f"\n  ✗  Decryption failed: {e}"))
        sys.exit(1)

    print(green("\n  ✔  File decrypted successfully!\n"))
    print(f"  {dim('KDF time     :')} {result['kdf_time_s']:.3f}s")
    print(f"  {dim('Decrypt time :')} {result['dec_time_s']*1000:.2f}ms")
    print(f"  {dim('Decrypted    :')} {human_size(result['decrypted_size'])}")
    print()


def cmd_inspect(args):
    """Handle the 'inspect' subcommand — show file metadata without decrypting."""
    try:
        info = inspect_file(args.input)
    except (FileNotFoundError, UnsupportedFileError) as e:
        print(red(f"  ✗  {e}"))
        sys.exit(1)

    print(f"\n  {bold('FENC File Inspector')}\n")
    print(f"  {dim('Magic          :')} {info['magic']}")
    print(f"  {dim('KDF            :')} {info['kdf']}")
    print(f"  {dim('Iterations     :')} {info['iterations']}")
    print(f"  {dim('Total size     :')} {human_size(info['file_size'])}")
    print(f"  {dim('Ciphertext     :')} {human_size(info['ciphertext_size'])} (includes 16-byte GCM tag)")
    print()


def cmd_benchmark(args):
    """
    Benchmark encryption speed across different file sizes and KDF settings.
    Creates temporary test files, measures performance, cleans up.
    """
    import tempfile
    import time as _time

    print(f"\n  {bold('Benchmark — AES-256-GCM encryption speed')}\n")
    password = "BenchmarkPassword123!"

    sizes = [
        (1 * 1024,           "1 KB"),
        (100 * 1024,         "100 KB"),
        (1 * 1024 * 1024,    "1 MB"),
        (10 * 1024 * 1024,   "10 MB"),
        (50 * 1024 * 1024,   "50 MB"),
    ]

    kdf_configs = [
        ("PBKDF2 (100k)",  False, 100_000),
        ("PBKDF2 (200k)",  False, 200_000),
    ]
    if ARGON2_AVAILABLE:
        kdf_configs.append(("Argon2id", True, 200_000))

    # Header
    print(f"  {'File Size':<12} {'KDF':<20} {'KDF Time':>10} {'Enc Time':>12} {'Throughput':>12}")
    print("  " + "─" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        for size, label in sizes:
            # Write random plaintext
            src = os.path.join(tmpdir, "plain.bin")
            dst = os.path.join(tmpdir, "enc.fenc")
            with open(src, "wb") as f:
                f.write(os.urandom(size))

            for kdf_label, use_argon2, iters in kdf_configs:
                result = encrypt_file(src, dst, password, use_argon2=use_argon2, iterations=iters)
                throughput = size / max(result["enc_time_s"], 1e-9) / (1024 * 1024)
                print(
                    f"  {label:<12} {kdf_label:<20}"
                    f" {result['kdf_time_s']:>9.3f}s"
                    f" {result['enc_time_s']*1000:>10.2f}ms"
                    f" {throughput:>10.1f} MB/s"
                )

    print()
    print(dim("  Note: KDF time is intentionally slow — this is the security cost that"))
    print(dim("  makes brute-force attacks expensive. Encryption itself (AES) is fast."))
    print()


# ── Argument parser ────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="fenc",
        description="File Encryption Tool — AES-256-GCM with password-based key derivation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python cli.py encrypt secret.pdf secret.enc
  python cli.py encrypt secret.pdf secret.enc --kdf argon2
  python cli.py decrypt secret.enc recovered.pdf
  python cli.py inspect secret.enc
  python cli.py benchmark
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input",  help="Path to the plaintext file")
    enc.add_argument("output", help="Path to save the encrypted file")
    enc.add_argument("--kdf", choices=["pbkdf2", "argon2"], default="pbkdf2",
                     help="Key derivation function (default: pbkdf2)")
    enc.add_argument("--iterations", type=int, default=PBKDF2_ITERS,
                     help=f"PBKDF2 iteration count (default: {PBKDF2_ITERS:,})")

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a FENC encrypted file")
    dec.add_argument("input",  help="Path to the encrypted .fenc file")
    dec.add_argument("output", help="Path to save the decrypted file")

    # inspect
    ins = sub.add_parser("inspect", help="Show metadata of an encrypted file")
    ins.add_argument("input", help="Path to the encrypted .fenc file")

    # benchmark
    sub.add_parser("benchmark", help="Benchmark encryption performance across file sizes")

    return parser


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "encrypt":   cmd_encrypt,
        "decrypt":   cmd_decrypt,
        "inspect":   cmd_inspect,
        "benchmark": cmd_benchmark,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
