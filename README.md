# cyberark-aim-cli

A simulation of the **client-side** secret retrieval and rotation logic
that applications use when talking to a CyberArk PAM deployment via AIM.

> This project is a **learning + portfolio artifact**. It does not talk to a
> real CyberArk vault — instead it implements the same concepts (encrypted
> storage, retry policy, audit trail, path authentication) against a local
> encrypted file. The goal is to demonstrate understanding of PAM mechanics
> without needing a licensed PAM server.

## What it demonstrates

- **Encrypted secret storage** using AES-256-GCM with PBKDF2-derived keys
- **Automated rotation** with retry + exponential backoff (mimics CPM)
- **Audit logging** on every read/write/rotate (mimics CyberArk audit)
- **Application path authentication** (allow-list of cwd paths)
- **CLI UX** — `add`, `get`, `rotate` commands

## Install

\`\`\`bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
\`\`\`

## Usage

\`\`\`bash
export AIM_PASSPHRASE="change-me"
aim add --account db-prod --username svc_app --password 'Init!123'
aim get --account db-prod
aim rotate --account db-prod
\`\`\`

## Limitations

- Password rotation is local only; no CPM central policy
- No vault HA / DR (production CyberArk is clustered)
- Auth is local passphrase; production uses dual control + PSM

## What I learned

The first version didn't handle retries when the vault write failed mid-run.
Adding exponential backoff made the tool behave like a real rotation job:
idempotent, logged, and observable.

## License

MIT

