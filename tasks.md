# Counselog — Implementation Plan

## Context

A supervisor's encrypted note journal. Capture freeform notes, bin them
(per-person / self / team) with a local LLM, read them back as per-person
digests. See `counselog-tech-spec.md` for the design, `CLAUDE.md` for the rules.

**Stack:** Python 3.12+ · Click (CLI) · Flask (read UI) · SQLCipher (storage) ·
`cryptography` (envelope encryption, mTLS) · Ollama (inference, desktop only)

**Scope:** v0/MVP per spec §9 — capture, bin tagging, encrypted storage on both
machines, one report (per-person digest), one dashboard metric (note frequency
and recency). Everything else deferred until real notes exist to design against.

---

## Phase Status

| Phase | Status | Machine |
|---|---|---|
| Phase 0 — Scaffold | ✅ Complete | desktop |
| Phase 1 — Crypto core | ✅ Complete (53 tests, 89% cov) | desktop (password + stub) |
| Phase 2 — Storage + hash chain | ✅ Complete (131 tests, 89% cov) | desktop |
| Phase 3 — Transport + mirror | ⬜ Not started | desktop (loopback) |
| Phase 4 — Bin tagging | ⬜ Not started | desktop |
| Phase 5 — Reports + dashboard | ⬜ Not started | desktop |
| Phase 6 — Flask read UI | ⬜ Not started | desktop |
| Phase 7 — PIV signing | ⬜ Not started | **laptop — needs the YubiKey** |
| Phase 8 — Harden + docs | ⬜ Not started | both |

Phases 0–6 are buildable entirely on the desktop. Only phase 7 needs the laptop.

---

## Phase 0 — Scaffold ✅

Delivered: `.gitignore` (secrets first, patterns verified against a scratch
repo), `pyproject.toml`, `CLAUDE.md`, `README.md`, `LICENSE`, package skeleton,
`./counselog` and `./counselogd` wrappers, venv with core deps installed.

**Decisions made during phase 0, with evidence:**

1. **Python 3.14 confirmed viable.** `sqlcipher3` 0.6.2 publishes cp314
   manylinux wheels and installs clean. `requires-python = ">=3.12"` so the
   laptop is not forced onto 3.14.

2. **SQLCipher verified working, not assumed.** SQLCipher 4.12.0 community via
   `sqlcipher3` 2.6.0. Confirmed on this machine: the raw-key form
   `PRAGMA key = "x'<64 hex>'"` round-trips; a wrong key raises `DatabaseError`;
   stdlib `sqlite3` reports "file is not a database"; the note text does not
   appear in the file; there is no `SQLite format 3` magic header — the file is
   ciphertext from byte 0.

3. **`yubikey-manager` demoted to an optional extra**, a change from the plan.
   `pyscard` publishes **no Linux wheels at all** (macOS and Windows only, PyPI
   as of 2026-08); on Linux it builds from sdist and needs `swig` plus
   `libpcsclite-dev`. The desktop has no YubiKey and never needs one — it gets
   the DEK over mTLS — so that toolchain cost is now the laptop's alone. Core
   dependencies dropped from 7 to 5. Import it lazily, inside the functions that
   use it.
   Laptop prerequisite: `sudo apt install swig libpcsclite-dev pcscd`

4. **Trial decryption needs an fd-level stderr guard.** SQLCipher's C layer
   writes `ERROR CORE ... hmac check failed` straight to fd 2 on a wrong key.
   Unlock tries each keyring entry in turn, so wrong keys are the *expected*
   path, and without suppression every unlock would spray C errors at the user
   (Law 6). `contextlib.redirect_stderr` does not catch it — only `os.dup2` on
   fd 2 does. Verified working. Belongs in `core/db.py` as a shared helper.

---

## Phase 1 — Crypto core ✅

`core/crypto/{factors,envelope,session}.py`, `core/paths.py`,
`laptop/keys_cli.py`. Commands: `keys init|add|list|revoke|test`.

Delivered as designed: one 32-byte DEK, wrapped once per factor into an atomic,
0600, no-secrets-inside `keyring.json`. YubiKey KEK is
`HKDF-SHA256(HMAC-SHA1(slot2, challenge))`; password KEK is scrypt at n=2**17
(measured 263 ms / 128 MB on this desktop). AES-256-GCM with AAD binding each
wrapper to its own id and factor.

**Decisions and findings:**

1. **`keys rotate` is deliberately NOT exposed yet.** The envelope primitive
   (`Keyring.rewrap_all`) is written and tested, but rotating the DEK without
   also re-keying the database would orphan every note. The CLI command lands in
   phase 2, next to `PRAGMA rekey`, so the two are always one operation.

2. **`rewrap_all` refuses unless every registered factor is present.** Rotating
   with the backup YubiKey in a drawer would silently lock that key out. It also
   swaps the wrapper list only after all re-wraps succeed, so a key pulled out
   mid-rotation leaves the old keyring intact.

3. **`revoke` refuses to remove the last wrapper** (Guideline 2), and says
   plainly that removing a wrapper is not retroactive — it cannot protect data
   against a key already copied or an older backup. Only rotation does.

4. **Factors take an injectable responder.** `YubiKeyFactor(responder=...)` lets
   the real derivation path be tested with a fake HMAC-SHA1 key on a machine
   with no YubiKey. This is why phase 1 could be completed on the desktop.

5. **Passwords are NFC-normalised before stretching.** Without it, an accented
   character entered as a combining sequence derives a different KEK and fails
   to unlock, with no clue why.

6. **scrypt parameters from the keyring are range-checked.** The keyring sits
   outside the encrypted database, so it is attacker-writable in the worst case;
   an unchecked `n` would let a tampered file wedge the process (Law 5).

7. **`FactorUnavailable` is distinct from a wrong key.** "Plug in your YubiKey"
   and "that is the wrong key" are different user problems and get different
   messages (Law 6).

**Verified YubiKey API, for phase 7** (probed from the real 5.9.2 package):

    from ykman.hid import list_otp_devices          # no pyscard needed
    from yubikit.core.otp import OtpConnection
    from yubikit.yubiotp import SLOT, YubiOtpSession
    YubiOtpSession(conn).calculate_hmac_sha1(SLOT.TWO, challenge) -> bytes

`ykman.device.list_all_devices` imports pyscard at module level; `ykman.hid`
does not. So the unlock path needs no smartcard stack at runtime even though pip
installs pyscard regardless. Confirmed importable with only `cryptography` and
`fido2` present.

**Not verified here:** `_hardware_responder` (factors.py:174-195) is the only
uncovered block. It cannot be exercised without a physical key — first real run
happens on the laptop.

## Phase 2 — Storage + hash chain ✅

`core/{db,models,chain,sanitize,paths}.py`, `laptop/{notes,people,unlock}_cli.py`.
Commands: `init`, `note`, `import`, `verify`, `forget`, `people add|list|remove`,
and `keys rotate` (held back from phase 1 until it could re-key the database in
the same operation).

**Design decisions and findings:**

1. **The chain hash is split in two: `body_hash` and `entry_hash`.** This was not
   in the plan and is load-bearing. `entry_hash = SHA256(prev_hash || body_hash)`.
   With a single combined hash, tombstoning — which deliberately destroys a body
   — would make that entry unrecomputable, so *every* tombstone would look
   exactly like tampering. Splitting them means a cleared note loses only the
   proof about its own text, while the sequence around it stays fully
   verifiable. Honouring a deletion request no longer destroys the evidence for
   everything else.

2. **Verification cross-checks notes against the chain, not just the chain.**
   Found while writing the tests: walking the chain alone never visits a note
   inserted straight into the `notes` table, so fabricated notes could be
   appended and still verify clean. History could not be *altered*, but it could
   be *added to*. `verify_chain` now reports any note no entry covers. Both
   attacks are tested end-to-end against a real encrypted database.

3. **Canonical form is length-prefixed, not delimited.** Four bytes of length in
   front of each field, so no note can be re-split at different boundaries to
   collide with another. Versioned in the hashed bytes, so a future change to
   the serialization cannot silently invalidate an old chain.

4. **Deletion is impossible at the database level.** A `BEFORE DELETE` trigger on
   `notes` refuses outright, and `note_chain` refuses both UPDATE and DELETE.
   Clearing text goes through `forget`, which tombstones. Tombstoning a
   fabricated note does *not* launder it — tested.

5. **`captured_at` immutability is a trigger, not a convention**, and it is
   narrow: `processed` and the tagging fields still update freely.

6. **Sanitization runs before hashing**, so the chain covers exactly what is
   stored. When it changes pasted text the CLI says so — silently altering a
   note the user pasted would be worse than not altering it (Law 6).

7. **`verify` states its own limits in its output.** A clean result says the
   notes are unaltered, then says plainly that this does not show what they say
   is true, nor exactly when events happened. The tool must not let a green tick
   imply more than it proves.

8. **Rotation is guarded.** Every registered factor must be present before
   anything changes; the old keyring is copied aside first; the database is
   reopened with the new key to confirm before reporting success; and the user
   is warned both that the desktop mirror will stop opening until the next sync,
   and that the backup keyring can still unwrap the old key and should be
   deleted.

9. **`--third-party` on import** sets `source_trust`, so the stronger
   sanitization of spec §10 can be applied later without guessing which notes
   were which.

**Deferred deliberately:** an orphaned note is *detected* but cannot be
*attributed* — the chain proves it was not recorded, not who added it. Signing
(phase 7) is what closes that.

## Phase 3 — Transport + mirror

`certs init`, `desktop/service.py`, `laptop/client.py`, `desktop/mirror.py`,
`doctor`, loopback mode.

- Local CA plus server and per-device client certs via `cryptography`'s X.509
  builder. Mutual TLS, CA pinned both sides. Server cert SANs carry both the
  tailnet MagicDNS name and the `100.x` address.
- Addresses in a gitignored `.env` (`COUNSELOG_DESKTOP_HOST`, `COUNSELOG_BIND`),
  never in source — the repo should be publishable without leaking topology.
- Bind to the tailnet interface, never `0.0.0.0`. Per-device client certs, not
  one shared cert, because §10's multi-device capture opens exactly this seam.
- `POST /session` carries the DEK; desktop holds it in memory with a TTL,
  returns a `session_id`; `DELETE /session/<id>` on exit. Nothing key-shaped
  ever touches the desktop's disk.
- **Loopback mode:** both halves on 127.0.0.1 against two separate DB files, so
  sync is testable here without the laptop awake.

Tests: handshake succeeds with the right CA, refused with a foreign client cert;
expired session rejected; sync idempotent on replay; DEK absent from disk after
a service restart.

## Phase 4 — Bin tagging

`desktop/tagger.py`; `counselog sync`, `review`.

- Stage 1: deterministic alias match against `people.aliases`, word-boundary and
  case-insensitive. Hits get `confidence = 1.0` and never reach the model.
- Stage 2: Ollama `/api/chat` with `format` set to a JSON Schema whose `bin`
  field is an enum of real bin keys, so the model cannot invent one.
  `temperature: 0`, fixed seed (Law 7).
- Benchmark `gemma4:12b` against `llama3.1:8b` on real tagging prompts before
  picking a default. Model name stays config.
- Tags below `auto_accept_threshold` (default 0.75) are surfaced by
  `counselog review`. Tags sit outside the chained body, so re-tagging never
  disturbs the chain.
- `sync` prints a one-line disclosure of what goes where, every time (Law 2).

Tests: alias matcher against a stub `people` table; Ollama client against a
local stub server asserting the schema is sent and an out-of-enum bin rejected.
No live model in unit tests.

## Phase 5 — Reports + dashboard

`desktop/reporter.py`; `counselog report`, `dash`.

- Per-person digest: chronological, deterministic cleanup only (whitespace and
  markdown). §9 says no synthesis; Law 7 wants predictable output. LLM polish
  sits behind an explicit `--polish`.
- Backdated notes shown at `backdated_at` with a visible marker.
- Dashboard: note count and days-since-last per person. Pure SQL, no LLM.

## Phase 6 — Flask read UI

`laptop/web/app.py`; `counselog ui`.

Launched from an already-unlocked CLI process so the DEK stays in one process.
Bound to 127.0.0.1, random token in the URL, strict CSP, no external assets.
Read-only: `/person/<id>` and `/dash`. Capture stays in the CLI.

## Phase 7 — PIV signing *(laptop)*

`core/crypto/signing.py`.

### Laptop setup checklist

A `Projects/` subfolder is ready on the laptop and `swig` is installed
(2026-08-30). Remaining, before `pip install -e ".[yubikey]"` will work:

| Need | Why | Status |
|---|---|---|
| `swig` | generates pyscard's bindings at build time | ✅ done |
| `libpcsclite-dev` | PC/SC headers; the build fails without them even with swig | ⬜ |
| `pcscd` | smartcard daemon; runtime requirement for PIV (phase 7) | ⬜ |
| udev rules | non-root access to the key over HID and CCID | ⬜ |

The udev rules are the easy one to miss: the pip wheel for `yubikey-manager` is
pure-python and bundles **no** rules, so without them a non-root user gets
permission errors talking to the key. Installing the distro package alongside
the pip one is the simplest fix — it is wanted for its udev rules and pcscd
wiring, not its Python code.

    sudo apt install swig libpcsclite-dev pcscd yubikey-manager

Key programming, once, before first use:

    ykman otp chalresp --generate 2      # phase 1: OTP slot 2, unlock factor
    ykman piv keys generate 9c ...       # phase 7: PIV slot 9c, signing key

Note that phase 1's unlock factor talks OTP over **HID** and does not need
pcscd; only phase 7's PIV signing needs the smartcard stack. But pip pulls
pyscard in either way, so the build dependencies are needed from the start.

ECDSA-P256 over the chain head at each sync, using PIV slot 9c — key generated
on-device, non-extractable, PIN per operation. Signing the head rather than each
note means one PIN per session, not one per note; capture stays as fast as
typing. `verify` gains signature checking.

## Phase 8 — Harden + docs

`SECURITY.md`, real two-machine run, docs pass.

`SECURITY.md` must state plainly what the chain and signature do **not** prove:
the chain shows the record is unaltered, the signature shows who held the key,
neither shows the note is *true*, and neither shows *when* the content was
authored — only when it was signed. Third-party proof of time needs an RFC 3161
authority, which leaks note counts and timing; the format reserves room for
anchor tokens, but v0 does not build it.

Also: recommend a tailscale ACL limiting the service port to the laptop, and
note that a real WSGI server replaces Flask's before this faces anything wider.
