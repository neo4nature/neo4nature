# MA Wallet (MA57 snapshot) — Web + Soft-Wallet Core

This bundle contains a working MA prototype with:
- **Flask web UI** split progressively into blueprints (`routes/`)
- **Service layer** for selected domains (`services/`)
- **Soft-wallet core** (`wallet/`: keys, signing, state)
- **Decision core** (`core/`: 5 mini-AI, AI kernel, Horizon)
- **Storage / chunking / assembly**
- **Signer boundary bridge** (`core/firmware_bridge.py`, `daemon/walletd.py`)
- **Security hardening v0** (same-origin mutation guard + lightweight rate limiting)

## Quick start (Ubuntu/Linux)

- `core/`
  - `ai_*` — five independent risk-check modules
  - `ai_kernel.py` — aggregates 5 modules (no final decision)
  - `horizon.py` — minimal final gate (ALLOW/BLOCK) over kernel output
- `wallet/`
  - `key_manager.py` — secp256k1 keys (software v0)
  - `tx_signer.py` — transaction signing
  - `state.py` — balances/state model
- `docs/`
  - protocol sketches and future hardware boundary plan
- `firmware/`
  - placeholder skeleton for the hardware wallet firmware tree (C)

## Notes on security

This is **software wallet v0** for testing and UX iteration.
Hardware isolation (Secure Element / MCU boundary) is planned in `docs/` and `firmware/`.

Current hardening in this snapshot:
- state-changing requests require same-origin / host match checks
- lightweight in-process rate limiting for sensitive endpoints
- optional worker tick token via `MA_WORKER_TICK_TOKEN`
- signer boundary tests cover INPROC + TCP walletd + CRC framing

## Firmware signer transport (v0.5)

This bundle supports a signer switch:
- **SOFTWARE**: signing happens inside Flask (per-user wallet key)
- **FIRMWARE**: signing happens via the host protocol
  - default transport is **SERIAL (PTY)** unless `MA_SIGNER_TRANSPORT=SOCKET` is set

Run firmware mode:

```bash
export MA_SIGNER_MODE=FIRMWARE
./run.sh
```

Optional daemon settings:

```bash
export MA_WALLETD_HOST=127.0.0.1
export MA_WALLETD_PORT=7788
export MA_WALLETD_TIMEOUT=2.0
```


## v0.1.3 — Kontrybucja (Suwak) + Storage (Pola)

W tej wersji dodano prototyp:
- **/wallet**: sekcja *Horyzont · Ogień i Pola* (suwak 0–100) oraz 4 pola storage (stage 0–7).
- **API**:
  - `GET/POST /api/contrib`
  - `GET /api/storage/fields`
  - `POST /api/storage/start`
  - `POST /api/storage/harvest`
  - `GET /api/receipts`

Nagrody są potwierdzane lokalnym **paragonem Horyzontu** (podpis Ed25519) i mogą być odebrane offline.


## Media + Chunking (prototype)

Wprowadzono podpisywane manifesty mediów (bez hostingu treści) oraz minimalny lokalny "blobstore" do chunkowania:

- **Media (manifesty)**: `/media` i `/media/new` → tworzysz manifest z listą chunków/CID i podpisujesz go portfelem.
- **Chunking tool**: `/storage` → wgrywasz plik, system tnie go na chunki, zapisuje w `data/blobstore/chunks/` i zwraca listę SHA-256 (1 na linię), którą wklejasz do manifestu.
- **Peer serve (prototype)**: każdy chunk jest dostępny pod `/storage/chunk/<sha256>`.

To jest świadomie minimalny szkielet — dystrybucja P2P/IPFS/swarm będzie kolejną warstwą.

## Runtime and data directories

By default the app stores mutable runtime markers in `./runtime/`. Data should be treated as operational, not authoritative without verification.

You can override the main data directory with:

```bash
export MA_DATA_DIR=/absolute/path/to/ma_runtime
```

Peer routing (optional): edit `runtime/peers.json` and add peer base URLs. The peer must expose `GET /api/blob/chunk/<sha256_hex>`.

## Snapshot status (MA57)
- compute cancel/refund path hardened
- worker tick can be protected by `MA_WORKER_TICK_TOKEN`
- routes split into blueprints for compute, auth/FID, feed, account, market/storage
- i18n moved out of `app.py` to `core/i18n.py`
- security hardening moved to `core/security.py`
- signer boundary tests added for `walletd` / bridge
- current regression suite: 22 passing tests
