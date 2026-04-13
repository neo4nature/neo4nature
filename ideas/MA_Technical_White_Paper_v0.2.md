# MA — Technical White Paper (v0.2 – update 2026-01-19)

## Cel dokumentu
Jednoznacznie opisać, jak MA działa technicznie, bez narracji marketingowej.

## 0. Zakres i założenia

## 0.1 Granice zaufania i katalogi danych (update 2026-01-19)

MA rozdziela **dane operacyjne**, **sekrety** oraz **podpis** na osobne domeny odpowiedzialności:

- **`MA_DATA_DIR`** – dane operacyjne: `ma.db`, segmenty Event Chain, blobstore/chunki, cache, receipts, logi.  
  Te dane mogą zostać utracone lub zmanipulowane przez hosta, dlatego **nie są autorytatywne** bez weryfikacji.

- **`MA_SECRETS_DIR`** – sekrety i artefakty kryptograficzne: zaszyfrowane vaulty, klucze urządzenia, materiały konfiguracyjne signera.  
  Zalecenie: osobny zaszyfrowany wolumen + minimalne uprawnienia (np. `0700`).

- **Signer / Firmware / Portfel** – jedyny komponent uprawniony do operacji podpisu kluczem prywatnym.
  Aplikacja hosta przekazuje wyłącznie `hash + purpose`, a wynik to podpis/receipt.

> **Runtime nie jest źródłem prawdy.** Jest tylko wskaźnikiem/markerem uruchomieniowym.

- Dokument opisuje kontrakty techniczne, nie UI.
- Źródłem prawdy jest Event Chain.
- AI = deterministyczne moduły strażnicze.
- Horyzont = minimalna procedura decyzyjna TAK/NIE.

## 1. Model zagrożeń (Threat Model)
### 1.1 Co chronimy
- klucze użytkownika
- integralność historii
- autentyczność decyzji
- poufność komunikacji
- poprawność rozliczeń

### 1.2 Przed czym
- replay ataki
- kradzież kluczy
- manipulacja UI
- podmiana historii
- spam / flooding
- nieuczciwy compute

### 1.3 Poza zakresem v0.x
- globalny Sybil resistance
- pełne P2P discovery
- reputacja społeczna

## 2. Tożsamość i klucze
### 2.1 Typy kluczy
- secp256k1 — podpisy użytkownika
- x25519 — komunikacja E2E
- ed25519 — Horyzont i urządzenia

### 2.2 Lifecycle klucza użytkownika
- generacja lokalna
- szyfrowanie (scrypt + AES-GCM)
- odszyfrowanie tylko do RAM
- podpisy przez portfel
- logout → wipe RAM

## 3. Portfel jako granica zaufania
### 3.1 Tryb firmware (host-minimal) (update 2026-01-19)

W trybie firmware (`MA_FIRMWARE_MODE=1`) host ogranicza funkcje do minimum:
- brak niepotrzebnych endpointów zapisujących dane na dysk,
- podpisy wyłącznie przez signer/portfel,
- UI pełni rolę widoku i klienta podpisu.

To tryb przygotowujący architekturę pod portfel sprzętowy i uruchomienie w środowisku o ograniczonych zasobach.

- jedyny podpisujący
- separacja hosta od klucza
- purpose-based signing

## 4. Device Identity
- ed25519 keypair urządzenia
- fingerprint
- binding user ↔ device

## 5. Event Chain
- append-only
- hash → prev_hash
- segmenty JSONL
- weryfikowalność

## 6. Rundy i Horyzont
- 5 modułów AI
- deterministyczne oceny
- decyzja TAK/NIE
- podpis i zapis do Event Chain

## 7. Storage

## 7.1 Filesystem Hardening (symlinki, traversal) (update 2026-01-19)

Warstwa hosta jest traktowana jako potencjalnie skażona. Minimalny zestaw obrony na poziomie plików:

- **Zakaz path traversal** (`..`, ścieżki absolutne, niedozwolone znaki) dla wszystkich ścieżek pochodzących z requestów.
- **Blokada symlink-escape**: pliki/katalogi wewnątrz `MA_DATA_DIR`/`PUBLIC_MEDIA_DIR` nie mogą być linkami prowadzącymi poza bazowy katalog.
- **Izolacja artefaktów publicznych**: wyniki compute i media publiczne są trzymane w wydzielonej przestrzeni, oddzielnej od sekretów i stanu systemu.
- **Walidacja przed odczytem i zapisem**: każdy odczyt/zapis przechodzi przez centralny resolver ścieżek.

Cel: nawet jeśli ktoś podstawia pliki w systemie (lub próbuje wymusić zapis w niechciane miejsce), aplikacja nie „ucieka” poza katalog bazowy.

- chunking SHA-256
- deduplikacja
- pinning i GC

## 8. Komunikacja E2E
- X25519 + HKDF + AES-GCM
- brak plaintext w DB

## 9. Compute (zalążek)
- task manifest
- proof of execution
- weryfikacja przez Horyzont

## 10. UI
- UI ≠ źródło prawdy
- tryb audytu

## 11. Znane braki
- recovery
- multi-sig
- peer discovery
- reputacja
- compute marketplace

## 12. Definicja v1
- każdy podpis ma proof
- każda decyzja ma receipt
- historia weryfikowalna
- portfel sprzętowy
- UI jako widok
- Runtime jako marker (nie domena zaufania); autorytet wyłącznie przez podpisy i weryfikację
