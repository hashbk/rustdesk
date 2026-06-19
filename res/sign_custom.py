#!/usr/bin/env python3
"""Sign custom client config and generate custom.txt.

Usage:
    python3 sign_custom.py --private-key-b64 <base64_private_key> --config <json_config_string> --output <output_path>

The private key should be a 64-byte Ed25519 key (seed + public_key) encoded in Base64,
compatible with sodiumoxide's sign::SecretKey format.

The config should be a JSON string containing the custom client configuration.

The output will be a Base64-encoded string of (signature + message),
compatible with sodiumoxide's sign::verify() format.
"""

import argparse
import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def sign_config(private_key_b64: str, config_json: str) -> str:
    """Sign the config JSON with the given Ed25519 private key.

    Args:
        private_key_b64: Base64-encoded 64-byte private key (seed + public_key, sodiumoxide format)
        config_json: JSON string of the custom client config

    Returns:
        Base64-encoded signed data (signature + message)
    """
    sk_bytes = base64.b64decode(private_key_b64)
    if len(sk_bytes) != 64:
        print(f"Error: Private key must be 64 bytes, got {len(sk_bytes)}", file=sys.stderr)
        sys.exit(1)

    # sodiumoxide format: first 32 bytes = seed, last 32 bytes = public key
    seed = sk_bytes[:32]
    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    # Sign the message
    message = config_json.encode("utf-8")
    signature = private_key.sign(message)

    # sodiumoxide sign format: signature (64 bytes) + message
    signed_data = signature + message

    return base64.b64encode(signed_data).decode("ascii")


def main():
    parser = argparse.ArgumentParser(description="Sign custom client config")
    parser.add_argument(
        "--private-key-b64",
        required=True,
        help="Base64-encoded 64-byte Ed25519 private key (sodiumoxide format)",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="JSON string of the custom client config",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output path for the signed custom.txt file",
    )
    args = parser.parse_args()

    # Validate JSON
    try:
        json.loads(args.config)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON config: {e}", file=sys.stderr)
        sys.exit(1)

    signed = sign_config(args.private_key_b64, args.config)

    with open(args.output, "w") as f:
        f.write(signed)

    print(f"Signed custom.txt written to {args.output}")


if __name__ == "__main__":
    main()
