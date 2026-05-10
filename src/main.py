"""Command-line entry point for RSA-OAEP file encryption."""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rsa import generate_keypair
from crypto import encrypt_file, decrypt_file
from keyio import save_public_key, save_private_key, load_key, to_public_key, to_private_key
from oaep import DecryptionError


def cmd_keygen(args):
    print("[*] generating " + str(args.bits) + "-bit key pair...")
    start = time.time()
    public_key, private_key = generate_keypair(args.bits)
    elapsed = time.time() - start
    save_public_key(args.pub, public_key)
    save_private_key(args.priv, private_key)
    print("[*] done in " + format(elapsed, ".2f") + "s")
    print("    public key:  " + args.pub)
    print("    private key: " + args.priv)


def cmd_encrypt(args):
    loaded = load_key(args.key)
    public_key = to_public_key(loaded)
    print("[*] encrypting " + args.input)
    start = time.time()
    encrypt_file(args.input, args.output, public_key, _progress)
    elapsed = time.time() - start
    print()
    print("[*] done in " + format(elapsed, ".2f") + "s, wrote " + args.output)


def cmd_decrypt(args):
    loaded = load_key(args.key)
    private_key = to_private_key(loaded)
    print("[*] decrypting " + args.input)
    start = time.time()
    try:
        decrypt_file(args.input, args.output, private_key, _progress)
    except DecryptionError as exc:
        print()
        print("[*] decryption failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
    elapsed = time.time() - start
    print()
    print("[*] done in " + format(elapsed, ".2f") + "s, wrote " + args.output)


def _progress(current, total):
    if total <= 0:
        return
    percent = (current * 100) // total
    sys.stdout.write("\r    progress: " + str(percent).rjust(3) + "%  (" + str(current) + "/" + str(total) + " bytes)")
    sys.stdout.flush()


def build_parser():
    parser = argparse.ArgumentParser(description="RSA-OAEP file encryption tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate a new RSA key pair")
    p_keygen.add_argument("--bits", type=int, default=2048, help="modulus size in bits (default: 2048)")
    p_keygen.add_argument("--pub", required=True, help="output path for the public key")
    p_keygen.add_argument("--priv", required=True, help="output path for the private key")
    p_keygen.set_defaults(func=cmd_keygen)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--input", required=True, help="plaintext input file")
    p_enc.add_argument("--key", required=True, help="public key file")
    p_enc.add_argument("--output", required=True, help="ciphertext output file")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--input", required=True, help="ciphertext input file")
    p_dec.add_argument("--key", required=True, help="private key file")
    p_dec.add_argument("--output", required=True, help="plaintext output file")
    p_dec.set_defaults(func=cmd_decrypt)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
