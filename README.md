# ACG CA2 Assignment 2

## Project Structure

```text
Project/
├── .gitignore
│
├── source files/
│   ├── crypto_utils.py             Shared cryptographic utilities
│   ├── client.py                   File transfer client
│   └── server.py                   File transfer server
│
└── deployment files/
    ├── setup_keys.py               Key generation script

```

---

## How to Use

Create and install environment (VENV)
#### Key Creation
```bash
python "deployment files/setup_keys.py"
```

#### Server Run (Terminal 1)
```bash
python "source files/server.py"
```

#### Server Run (Terminal 2)
```bash
python "source files/client.py" <path_to_file>
#Eg
python "source files/client.py" "C:\Users\JaneDoe\Documents\my_assignment.pdf"
```

#### Output
in ./recieved_files
- `<filename>.enc`: The file encrypted at-rest.
- `<filename>.sig`: The RSA digital signature of the original file.

---

## Implementation Overview

- **Authentication**: Challenge-response handshake using RSA-PSS digital signatures over a random nonce.
- **Key Derivation (KDF)**: HKDF-SHA256 derives independent keys for AES encryption and HMAC authentication using distinct domain separators.
- **Transport Security**: Encrypt-then-MAC using AES-256-CBC and HMAC-SHA256. The HMAC tag is verified in constant time before decryption.
- **At-Rest Protection**: Files are saved on disk encrypted with an independent AES-256 key.
- **Non-Repudiation**: The client generates an RSA digital signature of the original file hash, which the server stores alongside the encrypted file.


## Cryptographic Design

| Feature | Algorithm | Rationale |
|---|---|---|
| **Handshake / Non-Repudiation** | RSA-2048 / PSS | NIST-compliant key size; PSS padding offers randomized encoding and formal security proofs. |
| **Key Derivation (KDF)** | HKDF-SHA256 | Derives distinct session keys from a single master secret using domain separations. |
| **Symmetric Encryption** | AES-256-CBC | Confirms confidentiality with random, unique IVs generated per encryption. |
| **Authentication / Integrity** | HMAC-SHA256 | Authenticates the ciphertext (IV \|\| Ciphertext) to prevent tampering and oracle attacks. |
| **Constant-Time Verification** | `compare_digest` | Mitigates timing side-channel attacks during HMAC validation. |
