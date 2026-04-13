# MA

**MA is a local-first trust infrastructure where identity is a cryptographic key, truth is signed events, and applications are clients of a wallet-driven event system.**

MA is not a social platform, not a classic blockchain, and not a cloud-first SaaS.
It is a modular trust layer designed for publishing, communication, storage, and distributed work without giving the source of truth to a central server.

## Core Idea

In MA:
- **identity = key**
- **truth = signed event**
- **the wallet is the trust boundary**
- **the Event Chain is the source of truth**
- **the UI is only a view**

> Nothing becomes true without a signature.  
> Nothing remains trustworthy without verification.

## Why MA Exists

Most digital systems still depend on central databases, central accounts, and central operators.

That creates a structural weakness:
- accounts can be closed
- data can be modified
- interfaces can mislead users
- trust is delegated to institutions instead of proofs

MA moves trust from institutions to cryptography, verifiable history, and deterministic procedures.

## What MA Does

MA provides a modular trust core for multiple application layers:
- wallet-based identity and signing
- append-only Event Chain
- signed publishing and proofs
- end-to-end communication
- content-addressed storage
- compute jobs with proof of execution
- deterministic review by five guardian modules and Horizon receipts

## Architecture Principles

1. **The wallet is the only signing core**
2. **The Event Chain is the source of truth**
3. **Purpose-bound signing**
4. **UI is not truth**
5. **Modular growth**

## Quick Start

```bash
git clone https://github.com/neo4nature/ma.git
cd ma
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

## Raspberry Pi / Local Node Direction

MA is being prepared for lightweight node deployments, including Raspberry Pi.

Design goals:
- Python + SQLite core
- no unnecessary x86-only assumptions
- signer boundary preserved
- LAN peer discovery path
- minimal bootstrap for first-node deployment

## Philosophy

MA is built on a strict trust philosophy:
- truth is more important than convenience
- identity should emerge from keys, memory, and continuity
- the host system is useful, but not authoritative
- signatures matter more than appearances
- modular systems should grow without losing their core boundary

## Status

MA is under active development.
This repository represents an evolving trust infrastructure rather than a finished consumer product.
