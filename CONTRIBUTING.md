# Contributing

Thanks for your interest!

## Development setup
1. Install OS deps (Ubuntu 24.04):
   ```bash
   sudo apt update
   sudo apt install -y python3-venv python3-dev build-essential pkg-config libffi-dev libssl-dev softhsm2 opensc
   ```
2. Create venv and install:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -U pip
   pip install -r requirements.txt
   ```
3. Initialize SoftHSM2 token and run:
   ```bash
   bash ./scripts/02_init_softhsm.sh
   bash ./scripts/03_run.sh
   ```

## Rules
- Never commit private keys or token storage:
  - `state/`, `softhsm_tokens/`, `conf/`
- Keep the UI and docs in English.
