# Сorporate-pki-demo — PKI Lab (Corporate Digital Signature)

A lightweight PKI demo environment for **enterprise-style digital signatures** on **Ubuntu 24.04**:

- Issue signer certificates (X.509) from a local **Root CA**
- Store private keys in **SoftHSM2 (PKCS#11)** (non-extractable)
- Sign documents and verify validity (signature + trust chain + validity window + demo revocation)
- Clean English web UI for demos and screenshots

## Architecture
- **Root CA (lab mode):** CA private key stored on disk for fast setup
- **Signer:** RSA keypair generated and stored inside SoftHSM2 (PKCS#11)
- **Web App:** FastAPI backend + UI
- **Verification:** signature verification + CA trust check + demo revocation list

## Quickstart (≈ 30–60 min)

### OS dependencies
```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential pkg-config \
  libffi-dev libssl-dev softhsm2 opensc
```

### Setup & run
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

bash ./scripts/02_init_softhsm.sh
bash ./scripts/03_run.sh
```

Open: http://127.0.0.1:8000

## Demo flow
1) **Enroll** → issue a signer certificate from the Root CA (CN comes from the UI)  
2) **Sign** → upload a file and receive a Base64 signature  
3) **Verify** → upload file + signature and get validity result  
4) **Revoke (demo)** → mark certificate as revoked and verify again  

## CLI checks

Show slots:
```bash
SOFTHSM2_CONF="$PWD/conf/softhsm2.conf" softhsm2-util --show-slots
```

List token objects:
```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --list-objects
```

## GitHub Pages
Project page is built from `/docs`.

GitHub → **Settings → Pages → Deploy from branch → main /docs**

## Security notes
This repo is for learning/demos. Do **NOT** commit:
- `state/`, `softhsm_tokens/`, `conf/`
- any private keys (`*.key`, `ca_key.pem`, etc.)

## License
Educational use.

## Publishing on GitHub
See [GITHUB_SETUP.md](GITHUB_SETUP.md).
