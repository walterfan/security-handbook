# 🔐 Crypto Playground

An interactive Streamlit app to **generate, inspect and use** cryptographic
material — keys, X.509 certificates, and symmetric/asymmetric encryption —
all rendered in a readable, pretty format.

## Features

| Tab | What it does |
|-----|--------------|
| 🔑 **Key Pairs** | Generate RSA (2048/3072/4096) or EC (P-256/384/521) key pairs, optional passphrase, download PEM. |
| 📜 **Certificate** | Build a self-signed X.509 cert with CN/O/C, SANs, validity; shows parsed details. |
| 🔍 **Inspect** | Paste any certificate / private key / public key PEM and review it in a table (validity, fingerprint, key size, SANs…). |
| 🧩 **Symmetric** | Encrypt/decrypt with **AES-256-GCM**, **AES-256-CBC**, **ChaCha20-Poly1305**, **Fernet** (key derived via PBKDF2). |
| 🔀 **Asymmetric** | **RSA-OAEP** encryption, **RSA-PSS / ECDSA** sign & verify, and an **ECDH** shared-secret demo. |

## Setup & Run

```bash
cd example/crypto-playground
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Then open the URL shown (default http://localhost:8501).

## Project layout

```
crypto-playground/
├── app.py                 # Streamlit UI (5 tabs)
├── crypto_lib/
│   ├── keys.py            # key pair + cert generation & inspection
│   ├── symmetric.py       # AES-GCM / AES-CBC / ChaCha20 / Fernet
│   └── asymmetric.py      # RSA-OAEP, RSA-PSS/ECDSA sign, ECDH
├── requirements.txt
└── README.md
```

## Quick demos to try

1. **Cert round-trip**: Generate a cert in the Certificate tab → copy the PEM →
   paste into the Inspect tab to see fingerprint, SANs and validity.
2. **RSA encryption**: Generate an RSA key pair in the Key Pairs tab → paste the
   public/private keys into the Asymmetric tab → encrypt with the public key and
   decrypt with the private key.
3. **ECDH**: Run the ECDH demo to see Alice and Bob derive an identical shared key.

> ⚠️ **For learning/demo only.** Do not use generated material as production secrets.
