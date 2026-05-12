# RSA-OAEP-256 File Tool

Tugas Pemrograman Kriptografi & Keamanan Informasi Genap 2025/2026

## Group 1 Authors

- Fikri Massaid Wahab (2206083395)
- Fariska Fedira Ardhanariswari (2206815705)
- Rana Koesumastuti (2206083496)

RSA-OAEP-256 file encryption written in pure Python without external crypto libraries. CLI and GUI included.

## Features

- 2048-bit RSA key generation with Miller-Rabin primality testing
- OAEP padding following PKCS #1 v2.2 (RFC 8017)
- Pure Python SHA-256 (FIPS 180-4)
- CRT-based decryption for roughly four times the speed of the textbook formula
- Streaming I/O so files of any size can be processed without buffering them in memory
- Both a command-line interface and a Tkinter GUI

## Requirements

Python 3.8 or newer. Only the Python standard library is used at runtime.

## Command-line usage

Generate a key pair:

```
python src/main.py keygen --pub mykey.pub --priv mykey.priv
```

Encrypt a file:

```
python src/main.py encrypt --input plaintext.bin --key mykey.pub --output ciphertext.bin
```

Decrypt a file:

```
python src/main.py decrypt --input ciphertext.bin --key mykey.priv --output recovered.bin
```

## Graphical interface

```
python src/gui.py
```

The GUI exposes the same three operations across separate tabs (Generate Keys, Encrypt, Decrypt) plus an About panel. Long-running operations run on a background thread with a determinate progress bar.

## Building a standalone executable

The repository ships a small helper script that wraps PyInstaller. Build the binary on the same operating system you want to run it on, since PyInstaller does not cross-compile.

```
pip install pyinstaller
python build.py
```

The output is placed under `dist/`. On Windows the binary is named `RSA-OAEP.exe` and can be launched by double-clicking; on Linux and macOS the file is just `RSA-OAEP`.

## Key file format

Keys are stored as plain text with hex-encoded big-endian integers and PEM-style markers.

Public key:

```
-----BEGIN RSA-OAEP PUBLIC KEY-----
# Bits: 2048
n=<hex>
e=<hex>
-----END RSA-OAEP PUBLIC KEY-----
```

Private key (with CRT parameters):

```
-----BEGIN RSA-OAEP PRIVATE KEY-----
# Bits: 2048
n=<hex>
d=<hex>
p=<hex>
q=<hex>
dP=<hex>
dQ=<hex>
qInv=<hex>
-----END RSA-OAEP PRIVATE KEY-----
```

The CRT fields (`p`, `q`, `dP`, `dQ`, `qInv`) on a private key are optional. If they are missing, decryption falls back to the direct `m = c^d mod n` form.

## Tests

```
python tests/test_sha256.py
python tests/test_oaep.py
python tests/test_rsa.py
python tests/test_keyio.py
python tests/test_e2e.py
```

`test_e2e.py` generates a fresh 2048-bit key pair and round-trips every file in `samples/` through encrypt and decrypt, verifying that the recovered output matches the original byte for byte.

## Notes

- Encryption is non-deterministic: a fresh random seed is sampled for every block, so encrypting the same plaintext twice produces different ciphertexts.
- Decryption errors are surfaced as a single generic `DecryptionError` regardless of which validation fails, in line with RFC 8017 guidance.
- The maximum plaintext size per RSA block is `k - 2 * hLen - 2` bytes, which is 190 bytes for a 2048-bit modulus paired with SHA-256. Larger files are split into multiple blocks transparently.
