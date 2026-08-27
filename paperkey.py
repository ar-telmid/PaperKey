#!/usr/bin/env python3

import sys
import time
import getpass
import secrets
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type


# ================================================================
# Configuration & Constants
# ================================================================

MAGIC_MARK = b"pK"
VERSION = 0x08

KEY_SIZE = 32

TIMESTAMP_SIZE = 5
SALT_SIZE = 16

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16

HEADER_SIZE = (
    len(MAGIC_MARK)
    + 1
    + TIMESTAMP_SIZE
    + SALT_SIZE
)

CONTAINER_SIZE = (
    HEADER_SIZE
    + GCM_TAG_SIZE
    + KEY_SIZE
)

assert HEADER_SIZE == 24
assert CONTAINER_SIZE == 72


# Output files
OUTPUT_KEY = "file.key"
OUTPUT_TXT = "file.txt"
OUTPUT_PNG = "file.key.png"


# Argon2id parameters
ARGON2_TIME = 3
ARGON2_MEMORY = 16 * 1024       # 16 MiB / 16384 KiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32


# ================================================================
# Hex Helpers
# ================================================================

def clean_hex_text(text: str) -> str:
    """
    Remove all whitespace from a Hex string.

    Spaces, tabs and newlines are ignored.
    """
    return "".join(text.split())


def encode_hex(data: bytes) -> str:
    """
    Encode bytes as uppercase Hex.
    """
    return data.hex().upper()


def decode_hex(text: str) -> bytes:
    """
    Decode a Hex string into raw bytes.

    Whitespace is ignored.

    Raises:
        ValueError: if the input is empty, has an odd length,
                    or contains invalid Hex characters.
    """
    clean = clean_hex_text(text)

    if not clean:
        raise ValueError("Hex input is empty")

    if len(clean) % 2 != 0:
        raise ValueError(
            "Hex string length must be even"
        )

    try:
        return bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError(
            "Invalid Hex data"
        ) from exc


# ================================================================
# Timestamp Helpers
# ================================================================

def encode_timestamp(ts: int) -> bytes:
    """
    Encode Unix timestamp into 5 big-endian bytes.
    """
    if ts < 0 or ts >= (1 << (TIMESTAMP_SIZE * 8)):
        raise ValueError(
            "Timestamp out of 5-byte range"
        )

    return ts.to_bytes(
        TIMESTAMP_SIZE,
        "big"
    )


def decode_timestamp(data: bytes) -> int:
    """
    Decode 5-byte big-endian Unix timestamp.
    """
    if len(data) != TIMESTAMP_SIZE:
        raise ValueError(
            "Invalid timestamp byte length"
        )

    return int.from_bytes(
        data,
        "big"
    )


def format_timestamp(ts: int) -> str:
    """
    Format Unix timestamp as UTC.
    """
    return datetime.fromtimestamp(
        ts,
        tz=timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


# ================================================================
# Cryptographic Functions
# ================================================================

def derive_key(
    passphrase: str,
    salt: bytes
) -> bytes:
    """
    Derive a 32-byte AES-256 key using Argon2id.
    """
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def build_aad(
    magic: bytes,
    version: int,
    timestamp: bytes,
    salt: bytes
) -> bytes:
    """
    Build AES-GCM Additional Authenticated Data.

    AAD =
        MAGIC
        + VERSION
        + TIMESTAMP
        + SALT
    """
    return (
        magic
        + bytes([version])
        + timestamp
        + salt
    )


# ================================================================
# Container Functions
# ================================================================

def parse_container(
    container: bytes
) -> dict:
    """
    Parse and validate a 72-byte PaperKey v0x08 container.

    Layout:

        Offset  Size
        ----------------
        0       2    MAGIC
        2       1    VERSION
        3       5    TIMESTAMP
        8       16   SALT
        24      16   GCM TAG
        40      32   CIPHERTEXT
        ----------------
        Total   72
    """

    if len(container) != CONTAINER_SIZE:
        raise ValueError(
            f"Invalid container size: "
            f"{len(container)} bytes "
            f"(expected {CONTAINER_SIZE})"
        )

    magic = container[0:2]

    version = container[2]

    timestamp_raw = (
        container[
            3:
            3 + TIMESTAMP_SIZE
        ]
    )

    salt = container[8:24]

    tag = container[24:40]

    ciphertext = container[40:72]

    # Validate magic
    if magic != MAGIC_MARK:
        raise ValueError(
            f"Invalid Magic Mark: {magic!r}"
        )

    # Validate version
    if version != VERSION:
        raise ValueError(
            f"Unsupported Version: "
            f"0x{version:02X} "
            f"(expected 0x{VERSION:02X})"
        )

    timestamp = decode_timestamp(
        timestamp_raw
    )

    # The first 12 bytes of the 16-byte salt
    # are used as the GCM nonce.
    nonce = salt[:GCM_NONCE_SIZE]

    return {
        "magic": magic,
        "version": version,
        "timestamp_raw": timestamp_raw,
        "timestamp": timestamp,
        "salt": salt,
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext,
    }


# ================================================================
# Key Generation
# ================================================================

def generate():
    """
    Generate a new PaperKey container.

    Outputs:

        file.key
            The generated secret key as uppercase Hex.

        file.txt
            The encrypted container as uppercase Hex.

        file.key.png
            QR containing the raw container bytes
            using QR 8-bit Byte Mode.
    """

    print(
        f"[+] Generating "
        f"{KEY_SIZE}-byte random secret key..."
    )

    secret_key = secrets.token_bytes(
        KEY_SIZE
    )

    # ------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------

    timestamp = int(time.time())

    timestamp_raw = encode_timestamp(
        timestamp
    )

    # ------------------------------------------------------------
    # Random salt
    # ------------------------------------------------------------

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    # First 12 bytes are used as AES-GCM nonce
    nonce = salt[:GCM_NONCE_SIZE]

    # ------------------------------------------------------------
    # Master passphrase
    # ------------------------------------------------------------

    passphrase = getpass.getpass(
        "Enter Master Passphrase: "
    )

    if not passphrase:
        raise ValueError(
            "Passphrase cannot be empty"
        )

    # ------------------------------------------------------------
    # Argon2id
    # ------------------------------------------------------------

    print(
        "[+] Deriving AES-256 key via Argon2id..."
    )

    aes_key = derive_key(
        passphrase,
        salt
    )

    # ------------------------------------------------------------
    # Build AAD
    # ------------------------------------------------------------

    aad = build_aad(
        MAGIC_MARK,
        VERSION,
        timestamp_raw,
        salt
    )

    # ------------------------------------------------------------
    # AES-256-GCM encryption
    # ------------------------------------------------------------

    print(
        "[+] Encrypting secret key "
        "with AES-256-GCM..."
    )

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=GCM_TAG_SIZE
    )

    cipher.update(aad)

    ciphertext, tag = (
        cipher.encrypt_and_digest(
            secret_key
        )
    )

    # ------------------------------------------------------------
    # Build final container
    # ------------------------------------------------------------

    container = (
        MAGIC_MARK
        + bytes([VERSION])
        + timestamp_raw
        + salt
        + tag
        + ciphertext
    )

    if len(container) != CONTAINER_SIZE:
        raise RuntimeError(
            f"Internal error: generated container "
            f"is {len(container)} bytes instead of "
            f"{CONTAINER_SIZE}"
        )

    # ------------------------------------------------------------
    # Convert container to Hex for file.txt
    # ------------------------------------------------------------

    hex_container = encode_hex(
        container
    )

    # ------------------------------------------------------------
    # Convert secret key to Hex for file.key
    # ------------------------------------------------------------

    hex_secret_key = encode_hex(
        secret_key
    )

    # ------------------------------------------------------------
    # Save secret key
    # ------------------------------------------------------------

    Path(OUTPUT_KEY).write_text(
        hex_secret_key,
        encoding="ascii"
    )

    # ------------------------------------------------------------
    # Save encrypted container as Hex
    # ------------------------------------------------------------

    Path(OUTPUT_TXT).write_text(
        hex_container,
        encoding="ascii"
    )

    # ------------------------------------------------------------
    # Generate Binary QR
    # ------------------------------------------------------------

    qr_created = False
    
    
    try:
        import qrcode
        from qrcode.util import QRData, MODE_8BIT_BYTE

        print(
            "[+] Generating QR using "
            "raw binary container bytes..."
        )

        qr = qrcode.QRCode(
            error_correction=(
                qrcode.constants.ERROR_CORRECT_M
            ),
            box_size=10,
            border=4
        )
        
        qr.add_data(
            QRData(
                container,
                mode=MODE_8BIT_BYTE
            )
        )

        qr.make(
            fit=True
        )

        qr.make_image().save(
            OUTPUT_PNG
        )

        qr_created = True

    except ImportError:
        print(
            "[!] 'qrcode' library is not installed."
        )

        print(
            "[!] Skipping QR code generation."
        )
    
    # ------------------------------------------------------------
    # Output information
    # ------------------------------------------------------------

    print(
        "\n[✔] PaperKey v0x08 "
        "generated successfully"
    )

    print(
        "=" * 40
    )

    print(
        f"Version       : 0x{VERSION:02X}"
    )

    print(
        f"Creation Date : "
        f"{format_timestamp(timestamp)}"
    )

    print(
        f"Container     : "
        f"{len(container)} bytes"
    )

    print(
        f"Hex Length    : "
        f"{len(hex_container)} characters"
    )

    print(
        f"Key Output    : "
        f"{OUTPUT_KEY} (Hex String)"
    )

    print(
        f"Text Output   : "
        f"{OUTPUT_TXT} (Hex)"
    )

    if qr_created:
        print(
            f"QR Output     : "
            f"{OUTPUT_PNG} (Binary)"
        )

    print(
        "=" * 40
    )


# ================================================================
# Decryption
# ================================================================

def decrypt(
    input_file: str
):
    """
    Decrypt a PaperKey container from a Hex file.

    The input file MUST contain Hex.
    Base32 is not supported.
    """

    path = Path(
        input_file
    )

    if not path.is_file():
        raise FileNotFoundError(
            f"Input file "
            f"'{input_file}' not found"
        )

    # ------------------------------------------------------------
    # Read Hex file
    # ------------------------------------------------------------

    print(
        f"[+] Reading data from "
        f"{input_file}..."
    )

    try:
        raw_text = path.read_text(
            encoding="ascii"
        )
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Input file is not valid ASCII Hex text"
        ) from exc

    # ------------------------------------------------------------
    # Decode Hex
    # ------------------------------------------------------------

    print(
        "[+] Parsing Hex container data..."
    )

    try:
        container = decode_hex(
            raw_text
        )
    except ValueError as exc:
        raise ValueError(
            "Invalid Hex format"
        ) from exc

    # ------------------------------------------------------------
    # Parse container
    # ------------------------------------------------------------

    parsed = parse_container(
        container
    )

    print(
        f"[+] Detected PaperKey "
        f"v0x{parsed['version']:02X}"
    )

    print(
        f"[+] Creation Date: "
        f"{format_timestamp(parsed['timestamp'])}"
    )

    # ------------------------------------------------------------
    # Master passphrase
    # ------------------------------------------------------------

    passphrase = getpass.getpass(
        "Enter Master Passphrase: "
    )

    if not passphrase:
        raise ValueError(
            "Passphrase cannot be empty"
        )

    # ------------------------------------------------------------
    # Argon2id
    # ------------------------------------------------------------

    print(
        "[+] Deriving AES-256 key "
        "via Argon2id..."
    )

    aes_key = derive_key(
        passphrase,
        parsed["salt"]
    )

    # ------------------------------------------------------------
    # Build AAD
    # ------------------------------------------------------------

    aad = build_aad(
        parsed["magic"],
        parsed["version"],
        parsed["timestamp_raw"],
        parsed["salt"]
    )

    # ------------------------------------------------------------
    # AES-GCM authentication/decryption
    # ------------------------------------------------------------

    print(
        "[+] Verifying GCM integrity "
        "and decrypting..."
    )

    try:
        cipher = AES.new(
            aes_key,
            AES.MODE_GCM,
            nonce=parsed["nonce"],
            mac_len=GCM_TAG_SIZE
        )

        cipher.update(
            aad
        )

        secret_key = (
            cipher.decrypt_and_verify(
                parsed["ciphertext"],
                parsed["tag"]
            )
        )

    except ValueError as exc:
        raise ValueError(
            "Authentication failed: "
            "invalid passphrase or "
            "corrupted data"
        ) from exc

    # ------------------------------------------------------------
    # Save restored key as uppercase Hex
    # ------------------------------------------------------------

    hex_secret_key = encode_hex(
        secret_key
    )

    Path(OUTPUT_KEY).write_text(
        hex_secret_key,
        encoding="ascii"
    )

    # ------------------------------------------------------------
    # Output information
    # ------------------------------------------------------------

    print(
        "\n[✔] Key restored and "
        "authenticated successfully"
    )

    print(
        "=" * 40
    )

    print(
        f"Creation Date : "
        f"{format_timestamp(parsed['timestamp'])}"
    )

    print(
        f"Key Size      : "
        f"{len(secret_key)} bytes"
    )

    print(
        "GCM Integrity : OK"
    )

    print(
        f"Restored Key  : "
        f"{OUTPUT_KEY} (Hex String)"
    )

    print(
        "=" * 40
    )


# ================================================================
# CLI
# ================================================================

def print_usage():
    """
    Print command-line usage.
    """

    prog = Path(
        sys.argv[0]
    ).name

    print(
        f"Usage:\n"
        f"  {prog} generate\n"
        f"  {prog} decrypt [file.txt]\n"
    )


def main():
    """
    CLI entry point.
    """

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = (
        sys.argv[1]
        .lower()
    )

    try:

        # --------------------------------------------------------
        # Generate
        # --------------------------------------------------------

        if command == "generate":
            generate()
            return

        # --------------------------------------------------------
        # Decrypt
        # --------------------------------------------------------

        if command == "decrypt":

            input_file = OUTPUT_TXT

            args = sys.argv[2:]

            for arg in args:

                if arg.startswith("-"):
                    raise ValueError(
                        f"Unknown option: {arg}"
                    )

                input_file = arg

            decrypt(
                input_file
            )

            return

        # --------------------------------------------------------
        # Unknown command
        # --------------------------------------------------------

        print_usage()
        sys.exit(1)

    except KeyboardInterrupt:

        print(
            "\n[-] Operation cancelled "
            "by user.",
            file=sys.stderr
        )

        sys.exit(130)

    except Exception as exc:

        print(
            f"[-] Error: {exc}",
            file=sys.stderr
        )

        sys.exit(1)


# ================================================================
# Program Entry Point
# ================================================================

if __name__ == "__main__":
    main()