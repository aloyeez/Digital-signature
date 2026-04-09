# Digital Signature — RSA File Signing Tool

A desktop application for creating and verifying cryptographic digital signatures using a custom RSA implementation and SHA3-512 hashing. Built with Java and JavaFX.

---

## Overview

This project implements the full digital signature lifecycle from scratch — key generation, file hashing, signature creation, and verification — without relying on Java's built-in signature APIs. The goal was to understand and apply the underlying mathematics of public-key cryptography.

**Core workflow:**

```
[File] ──SHA3-512──▶ [Hash] ──RSA(private key)──▶ [Signature .zip]

[Signature .zip] + [Public Key] ──RSA decrypt──▶ [Hash] ──compare──▶ Valid / Invalid
```

---

## Features

- RSA key pair generation using cryptographically secure random primes
- File hashing with SHA3-512 (512-bit output)
- Block-based RSA encryption/decryption of the hash
- Signature packaging into a ZIP archive (`.sign` file inside)
- Public/private key export to `.pub` / `.priv` files (Base64-encoded)
- Signature verification by decrypting and comparing hashes
- JavaFX GUI with file metadata display (name, path, type, size, dates)

---

## Architecture

```
src/
├── Main.java              # JavaFX application entry point
├── Controller.java        # UI event handling and workflow orchestration
├── RSA.java               # RSA algorithm: key generation, encrypt, decrypt
├── DigitalSignature.java  # SHA3-512 hashing and Base64 utilities
├── FileReader.java        # File I/O utility
└── resources/
    └── sample.fxml        # JavaFX UI layout
```

### Class responsibilities

| Class | Responsibility |
|---|---|
| `Main` | Launches the JavaFX window |
| `Controller` | Handles all UI events; orchestrates signing and verification |
| `RSA` | Pure RSA math — prime generation, key derivation, encrypt/decrypt |
| `DigitalSignature` | SHA3-512 hashing, Base64 encode/decode |
| `FileReader` | Reads raw file bytes from disk |

---

## How It Works

### 1. Key Generation

Two large random primes `p` and `q` are generated using `SecureRandom` with a Miller-Rabin primality test (100 rounds of `isProbablePrime`):

```
N    = p × q                                        (modulus)
φ(N) = (p − 1)(q − 1)                              (Euler's totient)
e    = random odd integer where gcd(e, φ(N)) = 1   (public exponent)
d    = e⁻¹ mod φ(N)                                (private key, via extended GCD)
```

Public key: `(e, N)` — Private key: `(d, N)`

Both the exponent and modulus `N` are stored together in key files as `value|N`, so signatures can be verified independently of the signing session.

### 2. Signing a File

```
hash   = SHA3-512(file bytes)         → 64 bytes
hash64 = Base64(hash)                 → string
blocks = split hash64 into 6-char chunks
signature = [RSA_encrypt(block, d, N) for each block]
result = Base64(space-joined encrypted blocks)
```

The hash is split into 6-character blocks before encryption to ensure each block converts to a `BigInteger` smaller than the modulus `N`.

### 3. Verifying a Signature

```
load signature from .zip
load public key from .pub file
decode Base64 → encrypted blocks
decrypted = [RSA_decrypt(block, e, N) for each block]
compare decrypted string with expected hash
```

### 4. RSA Encryption / Decryption

Standard modular exponentiation via Java's `BigInteger.modPow`:

```
Encrypt:  C = M^e mod N
Decrypt:  M = C^d mod N
```

Text-to-number conversion uses a 9-bit-per-character binary encoding, supporting the full 0–511 character range (covering all ASCII and extended characters).

---

## Getting Started

### Requirements

- Java 11+
- JavaFX SDK

### Run

```bash
javac --module-path /path/to/javafx/lib --add-modules javafx.controls,javafx.fxml src/*.java
java  --module-path /path/to/javafx/lib --add-modules javafx.controls,javafx.fxml -cp src Main
```

Or open in **IntelliJ IDEA** — the `.iml` and library configuration are included in the repo.

---

## Usage

### Sign a file

1. Click **Select file** and choose any file
2. Click **Show keys** to generate a new RSA key pair
3. Optionally save the keys with **Save private key** / **Save public key**
4. Enter a username and click **Sign text** to produce the encrypted signature
5. Click **Save signature** to export it as a `.zip` archive

### Verify a signature

1. Click **Load public key** and select a `.pub` file
2. Click **Load zip** and select the signature `.zip`
3. Click **Check signature** — the decrypted hash appears in the result field

---

## Tech Stack

| | |
|---|---|
| Language | Java 11 |
| UI Framework | JavaFX |
| Hash Algorithm | SHA3-512 (`java.security.MessageDigest`) |
| Cryptography | Custom RSA over `java.math.BigInteger` |
| Randomness | `java.security.SecureRandom` |
| Packaging | ZIP via `java.util.zip` |

---

## Notes

- **Educational intent** — the RSA implementation intentionally omits padding schemes (like OAEP) to keep the mathematics transparent. Production systems should use `java.security.Signature` with proper padding.
- **Key size** is controlled by the `digitCount` argument in `generate_p_and_q(12)` — using 12-digit primes. Increase this value for stronger keys.
- **Block size** (`BLOCK_SIZE = 6`) ensures each chunk converts to a `BigInteger` smaller than `N`, preventing modular overflow during encryption.
