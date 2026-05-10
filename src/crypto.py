"""File-level RSA-OAEP encryption and decryption with streaming I/O."""

import os

from rsa import rsaep, rsadp
from oaep import oaep_encode, oaep_decode, DecryptionError, HASH_LEN
from number_utils import i2osp, os2ip


def modulus_byte_length(n):
    """Return the byte length needed to encode an integer modulo n."""
    return (n.bit_length() + 7) // 8


def max_plaintext_chunk(k):
    """Return the maximum plaintext bytes that fit in a single OAEP block."""
    return k - 2 * HASH_LEN - 2


def encrypt_file(input_path, output_path, public_key, progress_callback=None):
    """Encrypt input_path to output_path using RSA-OAEP block-by-block.

    The plaintext is split into fixed-size chunks. Each chunk is wrapped with a
    fresh OAEP block and encrypted independently. The progress callback, if
    given, is invoked as (bytes_read, total_bytes) after every block.
    """
    n = public_key["n"]
    k = modulus_byte_length(n)
    chunk_size = max_plaintext_chunk(k)
    if chunk_size <= 0:
        raise ValueError("modulus is too small for OAEP with this hash")
    total = os.path.getsize(input_path)
    processed = 0
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            encoded = oaep_encode(chunk, k)
            message_int = os2ip(encoded)
            cipher_int = rsaep(public_key, message_int)
            fout.write(i2osp(cipher_int, k))
            processed += len(chunk)
            if progress_callback is not None:
                progress_callback(processed, total)
    if progress_callback is not None:
        progress_callback(total, total)


def decrypt_file(input_path, output_path, private_key, progress_callback=None):
    """Decrypt input_path to output_path, reading one ciphertext block at a time.

    Raises DecryptionError if the input length is not a multiple of the
    modulus size or if any block fails OAEP decoding.
    """
    n = private_key["n"]
    k = modulus_byte_length(n)
    total = os.path.getsize(input_path)
    if total % k != 0:
        raise DecryptionError("ciphertext length is not a multiple of the modulus size")
    processed = 0
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            block = fin.read(k)
            if not block:
                break
            if len(block) != k:
                raise DecryptionError("truncated ciphertext block")
            cipher_int = os2ip(block)
            try:
                message_int = rsadp(private_key, cipher_int)
            except ValueError as exc:
                raise DecryptionError("decryption error") from exc
            encoded = i2osp(message_int, k)
            chunk = oaep_decode(encoded, k)
            fout.write(chunk)
            processed += k
            if progress_callback is not None:
                progress_callback(processed, total)
    if progress_callback is not None:
        progress_callback(total, total)
