# ShieldID: privacy-preserving student identity wallet

![status](https://img.shields.io/badge/status-educational%20prototype-orange)
![python](https://img.shields.io/badge/python-3.11%2B-blue)

A prototype digital student ID built on verifiable credentials and zero-knowledge proofs. A university issues a credential, the student keeps it in a wallet, and a third party (e.g. a campus bookstore) can confirm *"this person is an actively enrolled student"* without learning their name, ID number or anything else.

> **Prototype, not production software.** Educational MVP, not audited. Don't use it to protect real identities.

## Features

- **Zero-knowledge checks:** verifiers confirm a fact without seeing the credential.
- **Selective disclosure:** the student chooses which extra attributes to reveal.
- **On-chain issuer registry:** issuer public keys live on an Ethereum smart contract.
- **Revocation:** revoked credentials are rejected on the next presentation.

## Team

Built by a team of five students.

**My part:**
- Designed and implemented the **zero-knowledge proof layer**: Pedersen commitments for
  credential attributes and Schnorr-style proofs, so a verifier learns only that
  "enrollment status is active" and nothing else.
- Implemented **holder binding**: each presentation includes a proof of key possession tied to
  a fresh verifier challenge, which prevents replay and credential sharing.
- Built the **credential issuance and verification** logic, the **OAuth 2.0** authorization flow,
  the **Ethereum issuer registry** (Solidity) and **credential revocation**.
- Wallet authentication (password, PIN)

**Teammates:** frontend, security logging, SSRF/CSRF protections, HTTPS, and the student-controlled attribute disclosure, authenticator-app second factor. 

## What it does

- **Privacy-preserving checks.** A verifier can confirm a fact about a credential without seeing
  the credential's contents.
- **Student-controlled sharing.** The student decides whether any additional attributes are
  revealed.
- **Verifiable trust.** Issuer public keys are published to an Ethereum smart contract, so
  verifiers don't have to contact the university directly.
- **Revocation.** A revoked credential is rejected the next time it is presented.

## Run locally

Requires Python 3.11+ and a local Ethereum dev node such as [`anvil`](https://book.getfoundry.sh/getting-started/installation).

```bash
git clone https://github.com/<your-username>/<repo>.git && cd <repo>
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python setup_dev.py          # generates local secrets and a TLS certificate
```

Then, each in its own terminal and in this order:

```bash
anvil                         # local blockchain
python deploy_contract.py     # deploys the issuer registry (rerun if anvil restarts)
python issuer_app.py          # https://localhost:5002
python app.py                 # wallet + portal, https://localhost:5000
python verifier_app.py        # https://localhost:5001
```

Register a wallet at <https://localhost:5000> (accept the self-signed certificate warning), request a credential with demo login `sara222` and the password printed by `setup_dev.py`, then present it to the verifier at <https://localhost:5001>.

## Limitations

This is a prototype built to demonstrate the concepts. Notably, all data is held in memory, the
wallet runs on a server rather than on the user's device, the blockchain is a local dev chain,
and the elliptic-curve library used is not side-channel resistant. A production system would
need to address each of these.

## Disclaimer

This is an independent educational project. It is not affiliated with, endorsed by, or
representing the University of Jordan or any other institution; the name is used only to
model a realistic scenario, and all student data in the demo is fictional.
