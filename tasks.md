# Counselog — Implementation Plan

## Context

A supervisor's encrypted note journal. Capture freeform notes, bin them
(per-person / self / team) with a local LLM, read them back as per-person
digests. See `counselog-tech-spec.md` for the design, `CLAUDE.md` for the rules.

**Stack:** Python 3.12+ · Click (CLI) · Flask (browser UI) · SQLCipher (storage) ·
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
| Phase 3 — Transport + mirror | ✅ Complete (184 tests, 89% cov) | desktop (loopback) |
| Phase 4 — Bin tagging | ✅ Complete (250 tests, 90% cov) | desktop |
| Phase 5 — Web foundation | ✅ Complete (283 tests, 90% cov) | desktop |
| Phase 6 — The browser interface | ✅ Complete (567 tests, 91% cov) | desktop |
| Phase 7 — PIV signing | ✅ Complete — first hardware signature 2026-10-21 | laptop — needs the YubiKey |
| Phase 8 — Harden + docs | 🟨 `SECURITY.md` done | both |

Phases 0–6 are buildable entirely on the desktop. Only phase 7 needs the laptop,
which is now the whole of what is left before hardening.

Phase 6 absorbed what earlier drafts listed as separate reports and read-UI
phases. Once the interface moved to a browser (phase 5), a "Flask read UI" was
no longer a phase of its own — it is what phase 6 builds — and reports are pages
in it rather than a thing that comes first.

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

## Phase 3 — Transport + mirror ✅

`core/{certs,config,protocol}.py`, `desktop/{service,sessions,mirror}.py`,
`desktop/__main__.py`, `laptop/{client,transport_cli}.py`, `.env.example`.
Commands: `certs init|enroll`, `doctor`, `sync`.

**Verified on this machine, in loopback:** `doctor` reports each step
separately; `sync` moved notes into the mirror; the mirror on disk has no SQLite
header and no note text; the mirror's chain reproduces the laptop's hashes
exactly; a certificate from a different authority is refused at the handshake;
and after restarting the service, `/mirror/status` and `/sync` both refuse
without a fresh session — the borrowed key did not survive.

**Bugs found and fixed while building:**

1. **The shutdown handler deadlocked.** `server.shutdown()` blocks until
   `serve_forever()` returns, and it was being called from a signal handler
   running on that same thread. The service ignored SIGTERM and had to be
   killed outright — which matters because the shutdown path is what discards
   the borrowed keys, so they stayed in memory until SIGKILL. Now both steps run
   on a separate thread; verified exiting in about a second, with the keys
   dropped.

2. **`doctor` hung for 30 seconds** against a port that accepts a connection but
   never completes a handshake. It now uses a 5-second timeout: doctor is what
   you run when something is already wrong.

**Design decisions:**

3. **A note travels with its chain entry, and the desktop recomputes the hash
   before storing anything** (`NotePayload.verify_self_consistency`). A mirror
   that accepted a note not matching its entry would be a mirror of something
   that never existed. Tombstoned notes skip the body check — their text was
   destroyed deliberately — but their link is still checked, the same split the
   local chain uses.

4. **Batches are all-or-nothing and must be contiguous.** A partially applied
   batch would leave a gap in the mirror's chain, which is indistinguishable
   from tampering ever after. Re-sending is a no-op, so an interrupted sync is
   safe to simply run again.

5. **Sessions are bound to the client certificate.** A session id leaked to
   another enrolled device does not work there — the certificate and the
   session must agree, and a mismatch is refused without confirming the session
   exists.

6. **The server certificate always covers loopback**, so the development mode
   needs no configuration. Mutual TLS is the real gate, not the name in the
   certificate, so a generous SAN list costs nothing and removes a class of
   confusing handshake failures.

7. **Per-device client certificates from the start**, with `certs enroll` for
   the next one. Spec §10's multi-device capture opens exactly this seam, and a
   shared certificate would mean revoking one device revokes them all.

8. **`COUNSELOG_CERTS` overrides the certificate location**, which the tests use
   so they never write into the repo.

9. **Errors never echo internals to the wire.** The 500 handler returns a fixed
   sentence: an exception message could carry a path, a query, or note text.

## Phase 4 — Bin tagging ✅

`desktop/tagger.py`, `laptop/tag_cli.py`, `/people` and `/tag` endpoints,
protocol support for people and tags, bin-key mapping and tag storage in
`core/models.py`. Commands: `tag`, `review`.

### Model benchmark (measured on this desktop, not assumed)

Five hand-labelled notes, warm models, schema-constrained output:

| model | correct | seconds/note |
|---|---|---|
| phi3:mini | 2/5 | 1.9 |
| llama3.1:8b | 2/5 | 2.7 |
| mistral:7b | 2/5 | 3.6 |
| deepseek-r1:7b | 3/5 | 53.8 |
| **deepseek-r1:14b** | **4/5** | **87.6** |

The reasoning models are 20-30x slower and substantially better. The small ones
were biased toward answering yes to everything — llama3.1:8b tagged "Tom asked
for Friday off" as `team`. Default is now `deepseek-r1:14b`, matching what
Charlotte found; the model name stays config.

The accuracy column is directional, not a score: the labels are one person's
reading of what "self" and "team" mean, and at least two of the five are
arguable. Real notes are the real test.

### The question put to the model got smaller

First attempt asked the model to choose from *all* bins. That took 47-294
seconds per note and produced confident nonsense — an 8B model tagged a note
with a person who was never mentioned in it. Aliases already resolve people
exactly, so the model is now asked only what aliases cannot answer: is this
about you, or about the team as a whole? Smaller question, far more reliable.

Verified end to end against the live model: 4/4 notes tagged correctly, two of
them by alias alone at no model cost.

### Bugs found and fixed while building

1. **Batching discarded everything on interruption.** Tagging all notes in one
   request meant ten minutes of model work was lost when the connection
   dropped, with no output the whole time. Now one note per request, results
   saved as they arrive, live progress, and `tag` resumes where it stopped.

2. **A long run expired its own session.** Tagging 20 notes takes far longer
   than the 15-minute idle timeout. Sessions now renew on use — but with an
   absolute one-hour cap, so renewal extends an active session rather than
   making a borrowed key immortal.

3. **A test called the real model** and hung the suite. An autouse fixture now
   makes any unstubbed call fail loudly instead.

4. **Progress output used a carriage return unconditionally**, which is right in
   a terminal and a mess in a log. It now checks for a tty.

### Design decisions

5. **Exact matches record no confidence at all** (NULL), which is exactly what
   spec §5 describes. Only model guesses carry a number, so `review` stays short
   enough to actually work through — names that are literally present are never
   second-guessed.

6. **The model runs even when a name matched.** A note can name someone *and* be
   about the team; skipping the second question whenever a name appeared would
   silently lose that.

7. **Tags travel by stable key** (`self`, `team`, `person:<id>`), never by bin
   id, because ids are auto-increment and may legitimately differ between the
   laptop and the mirror.

8. **Re-tagging replaces rather than accumulates**, so correcting an alias and
   running again converges. Tags sit outside the hashed note body, so none of
   this disturbs the chain — tested.

9. **A nonsense confidence falls back below the threshold.** A model returning 7
   has misunderstood the question, and treating that as certainty would
   auto-accept a tag nobody checked.

### Found in real two-machine use

10. **Tagging is not reproducible, and the model is not the reason.** Measured
    here: four back-to-back calls with the same note gave byte-identical
    answers, but the same note answered `self` (0.9) alone and *no bins at all*
    when sent straight after a different note. Every request is stateless and
    carries its own complete prompt, with `temperature: 0` and a fixed seed —
    the variation comes from the served runtime reusing cached state between
    requests, and cannot be switched off from here. Recorded in the tagger's
    docstring. It is why tags are reviewed, why re-tagging replaces rather than
    accumulates, and why no part of the interface promises repeatability.

11. **A desktop left running across an update serves its old endpoints.**
    `./counselog tag` failed with "No such endpoint" against a `counselogd`
    started before phase 4. `SERVICE_VERSION` now means something: the laptop
    declares what it needs, and `doctor`, `sync` and `tag` all check before
    doing slow work. `doctor` gained an "up to date" line.

12. **The desktop was holding the laptop's private key.** `certs init` generates
    each device's key there for transfer, and nothing removed it afterwards — so
    a break-in on the desktop would also yield the laptop's identity.
    `counselog certs prune` deletes other devices' private keys while keeping
    their certificates, and `certs init` now says to run it. Done on the real
    desktop.

13. **`doctor` misread as describing the peer.** "it sees us as 'laptop'" is the
    Common Name of the certificate *we* presented, which confused matters when
    run on the desktop, since that machine also held `laptop.crt`. Now: "we
    identify as 'laptop' (from certs/laptop.crt)".

14. **A note matching no bin vanished silently.** It appears in no report and
    `review` never shows it, because there is no guess to review. `tag` now
    lists them and says they will not appear in any report.

15. **Progress output padded with spaces**, so the tail of a longer previous
    line showed through. Now erases to end of line, and only in a terminal.

## Phase 5 — Web foundation ✅

Architecture revised: the interface moves to a browser served from this desktop
over the tailnet. See the approved plan for why and what it costs. Delivered:
`core/crypto/memory.py`, `web/{app,identity,sessions,ratelimit}.py`, templates
and stylesheet, `./counselogweb`.

**A fix that applies to the code already running.** This machine has 119 GB of
unencrypted swap, so a key held in memory can be paged to disk in plaintext and
survive power-off — defeating "a stolen disk is inert ciphertext". `DekSession`
now holds the key in an `mlock`ed buffer. Honest limits: the DEK is handed to
SQLCipher as a string and Python makes transient copies that cannot be pinned,
so this narrows the window rather than closing it. **The durable fix is
encrypting swap**, which is outside this program.

**The identity header is only trusted from the proxy.** `tailscale serve`
forwards to loopback and adds headers naming the caller, but any local process
could set those itself. `web/identity.py` requires both a loopback peer and the
header; a request from the LAN carrying a forged header is refused with 403,
verified against a running server.

**Sign-in became a denial-of-service surface.** scrypt costs ~260 ms and 128 MB
by design — the property that makes a stolen keyring expensive to attack also
means a few concurrent attempts exhaust 14 GB. `web/ratelimit.py` caps
concurrency and limits attempts, and the check runs *before* any derivation:
refusing afterwards would still let an attacker spend the memory.

**Locking is aggressive because capture will not need it.** 5 minutes idle,
30 minutes absolute, key dropped when the last session ends, and Lock ends every
session rather than just the current one — pressing Lock means close the notes,
and leaving another browser holding the key would not be that.

Two small bugs found by running it: Flask injects its own `session` into every
template, silently shadowing ours wherever a route did not pass one (renamed to
`unlocked` and injected globally); and an unconfigured `tailscale serve` answers
`{}`, which is truthy, so the startup check reported "serving something, but not
this port" when nothing was served at all.

**Not yet done:** `tailscale serve` needs one privileged setup step on this
machine before any browser can reach it.

## Phase 6 — The browser interface

`counselogweb`. Capture, reading, and reports, all in the browser served over
the tailnet. Four parts, all done.

### Part 1 — the sealed spool ✅

`core/spool.py`, schema version 2. A note can be written with no key available:
it is sealed to a public key and set aside, and the next sign-in judges it
against a hash chain over the entries and a per-device MAC. See the commit for
the full reasoning; the short version is that the locked server accepts and the
unlocked server judges.

### Part 2 — capture, enrolment, and the drain ✅

`core/{devices,intake}.py`, `web/access.py`, `web/views/{auth,capture,devices,held}.py`,
`web/static/{stamp,capture}.js`, capture/devices/held templates, schema
version 3. The capture box is now the home page, and `counselog init` publishes
the spool's public key so writing works from the moment the database exists.

**Two capture paths, split exactly on the key.** Signed in, a note goes straight
into the record; locked, it is sealed to the spool. One path for both — always
spool, drain at sign-in — was the first design and was wrong: a note you had
just written would be invisible until you signed in again, and an unenrolled
browser would have its notes held even while its user was sitting there
unlocked. The split costs a branch and removes both problems.

**The stamped bytes stopped being JSON.** They are the one thing in Counselog
produced in a browser and checked in Python, and JSON implementations do not
agree on escaping control characters, non-ASCII or lone surrogates. A
disagreement would hold a genuine note for review and look exactly like
tampering. They are now length-prefixed the way the chain already does it
(`chain.length_prefixed`, promoted from private). `tests/test_web_capture.py`
runs `web/static/stamp.js` under node and compares bytes *and* HMACs against
Python over accented text, Japanese, emoji, tabs, quotes and backslashes.

**A form submission rewrites every newline as CRLF.** Found by writing the test,
not by reading the code. The browser stamps the text it holds, which uses plain
newlines, so without normalising on both sides *every multi-line note* would
have failed its check — the feature would have worked for one-line notes and
quietly failed for real ones. `sanitize.normalize_newlines` is now the shared
definition, and the JavaScript carries the same two replacements.

**`captured_at` comes from this machine's clock, never the device's claim.** The
claim is inside what the device stamps, so it cannot be moved after the fact,
but it is still a phone's clock — and `captured_at` is the field that has to
mean something in an HR conversation. One clock, ours. A device more than five
minutes out is reported rather than quietly corrected.

**The spool file needed a name of its own.** Also found by a failing test: the
first design detected a replaced spool by noticing it was *shorter* than the
bookmark, which a file deleted and rebuilt to the same length walks straight
past. The bookmark now records which file it was reading, and the two anomalies
are handled differently because the right answer differs:

  - **Replaced** (a different file): nothing in it was ever taken in, so it is
    read from the start. Notes in the old one are gone — deleting the file
    destroys notes, it cannot add any — and that is reported.
  - **Altered** (the same file, with the entry the drain stopped at changed):
    reading from the start would file notes into the record a *second* time, so
    reading carries on from the bookmark and the chain check does the rest. A
    note written straight after the edit is held rather than filed, which is the
    chain working: an attacker cannot make an edit invisible by writing over it.
    Reading catches up on the next drain, so the effect is bounded.

**Quarantine is written down, not just reported.** An entry that fails a check
is evidence that something wrote to the spool that should not have, and evidence
that evaporates when the service restarts is not evidence. The *text* is not
kept: an entry that failed its checks has not earned a place in the record, and
storing it would build a second, unverified pile of notes beside the real one.

**The published public key is rewritten from the private half at every
sign-in.** It is the one file an attacker could usefully replace — swap in their
own key and the locked server would seal tomorrow's notes where they could read
them. Republishing bounds that to a single reading session, and notes sealed to
the wrong key surface in the quarantine instead of vanishing.

**Nothing is refused at capture that would cost a note.** A device id that is
not ours, a stamp of the wrong shape, a timestamp in the wrong form: all are
normalised to something the drain will recognise as unstamped, and the writer is
told *at the time* that the note will be held. Scripting off is the same path,
and the page says so in a `<noscript>`. The only refusals are an empty note and
one past the length cap, and the second keeps the text in the box.

**Enrolment is the one part of capture that needs the passphrase** — once per
browser, not once per note, because the key a browser is given has to be written
somewhere only an unlocked server can read. It is shown once and no route will
show it again.

**A spooled note outlived `forget`.** Found by looking at the real spool after
the first live note, not by the tests. The drain advanced its bookmark and left
the entry in place, body and all — correct for the chain, wrong for everything
else. `counselog forget` tombstones a note's text in the record and has never
heard of the spool, so any note written while locked kept a complete sealed copy
in a second file, recoverable by anyone who could open the spool key. Phase 2
built tombstoning precisely so a deletion request could be honoured; this
undermined it for exactly the notes the newest feature captures.

Fixed the same way the record already handles it: `clear_bodies` empties a
drained entry's body and keeps its row, so the link survives the text. It runs
as a sweep over the whole drained range at every drain rather than as a step
beside each note, so the file heals itself after an interruption — or after a
build that never cleared at all. Quarantined entries keep their bodies: their
text is not in the record, so the spool holds the only copy of what may be a
genuine note. `PRAGMA secure_delete` and a vacuum afterwards; both narrow the
window rather than close it, since a copy-on-write filesystem or an SSD's wear
levelling can keep an old page alive regardless.

The first version of that test was worthless and passed with the fix disabled:
it grepped the file for the note's words, and a sealed body is ciphertext, so it
would never have found them either way. It now opens the leftovers with the real
private key. Checked by disabling the fix and watching all four tests fail.

Two housekeeping items. The routes moved to `web/views/` with shared helpers in
`web/access.py`, because `web/app.py` was heading past the 600-line cap.
And migrations gained tests: they were checked by hand against a database built
by the previous release, which does not survive the release after next.
`tests/test_migrations.py` takes a current database apart to imitate versions 1
and 2, and checks the notes and the chain survive coming forward.

### Part 3 — reading back, and the subject registry ✅

Four slices, sequenced to keep the one that needs a schema change last, and to
give something playtestable after each.

**Slice 1 — the notes list, one note, and clearing one ✅**
`core/display.py`, `web/views/notes.py`, `notes.html`, `note.html`. Before this
there was no way to read a note back in *either* interface. Clearing goes
through the same tombstone as `counselog forget`, behind a confirmation page
that shows the text it is about to destroy — a dialog is easy to dismiss
without reading, and this is the one irreversible thing the interface can do.
`_friendly` and `_preview` moved out of `laptop/notes_cli.py` into
`core/display.py`, so a note reads the same in the terminal and on a phone.

**Cloud spellcheck was quietly on.** The capture textarea set no `spellcheck`
attribute, so it inherited the browser default — and Chrome's "enhanced spell
check" and Edge's Microsoft Editor send what you type to their servers. The
README promises the notes are never unencrypted off your chosen devices; that
was false for anyone with that setting on, and nothing disclosed it (Law 2). Now
`spellcheck="false"` explicitly, with the reason in the template so nobody
"tidies it up" later.

**Slice 2 — the subject registry ✅** (no schema change needed)
`models.update_person`, `web/views/people.py`, `people.html`, `person.html`.
Aliases could only be set when a person was created, with no way to add one
later or fix a spelling — which quietly cost accuracy, since aliases are what
resolve a name *exactly* and an exact match is the one answer the model is never
asked to second-guess. Now editable, along with renaming.

`update_person` takes a sentinel for pronouns rather than defaulting to None,
because None is itself a value here — "nobody has been asked" — and is a
different thing from "leave what is recorded alone". The interface keeps all
three states apart: not asked yet (NULL), they told you (the text), and asked
but preferred not to say (`''`). Choosing "they use" and typing nothing is
refused rather than quietly filed as never-asked, which would lose an answer
that was actually given.

**The three-way pronoun control became one field.** Playtesting kept catching
faults in it — ghost text that read as a value already set, a `<label>` shared
between the radio and the box so the box had no accessible name, and typing
pronouns while "Not asked yet" stayed selected discarding them silently. Each
was fixed, and then the control itself went: filled means known, empty means
nobody has said. All three faults become impossible rather than fixed, because
the mechanism causing them is gone.

What that gives up is "asked, and preferred not to say" — the one thing the
third state bought was a reminder not to ask again, in exchange for asking the
user to file someone's refusal. The column still keeps `''` distinct from NULL
and `Person.pronouns_withheld` still reads it, because losing that would need a
migration to get back; nothing in the browser writes it.

The fixes that led there, kept for the reasoning:
Raised in playtesting. A placeholder reading "she/her" is low-contrast, vanishes
the moment you type, and — in this field above all — reads as a value already
set, presenting a guess at someone's pronouns as though it were recorded. Moved
below the field as a real example. Two more faults surfaced while fixing it: the
radio and the text box shared one `<label>`, so the box had no accessible name
of its own; and typing pronouns while "Not asked yet" stayed selected silently
discarded them. The contradiction is now refused in both directions, with what
was typed still in the form, and a few lines of script tick "They told me" when
you type — an improvement on top of the server check, never the thing holding it
together.

"Left the team" stays a status flag and the page says what it does not do:
`tag` sends people with `include_inactive=True` and `notes_for_bin` ignores
`active`, so a former colleague still resolves in new notes and their old notes
stay readable. Nothing about the record changes.

Still CLI-only asymmetry, deliberately left: `counselog people add` has no
`--pronouns` and there is no `people edit`. The browser is the interface people
will actually use for this, and a second path to the same edits is a second
thing to keep correct. Worth adding if the CLI ever becomes the primary way in.

Pronouns are not sent to the mirror — `PersonPayload` carries name, aliases,
active and created_at only. The desktop does not need them to tag, and less on
the mirror is better. Revisit when reports start writing sentences about people.

**Slice 3 — editing a note, as revisions ✅** (schema version 4)
`core/revisions.py`, `notes.supersedes`, `note_chain.canon_version`, canon
version 2, edit routes and the revision history on the note page.

An edit appends. The correction is a new note pointing back at the one it
replaces; the original keeps its text, its hash and its place in the chain.
Editing in place was never really on the table — it would re-hash the body and
make `verify` report the note as altered, which is exactly what it *should*
report, and `note_chain`'s trigger refuses the UPDATE regardless.

**`supersedes` had to be hashed, and that forced a canon version.** The link
decides which text the record currently *says*, so leaving it outside the chain
would let a note be buried behind a fabricated revision with `verify` still
clean — the tool vouching for a history it had stopped showing. Hashing it
changes the note serialisation, so `CANON_VERSION` went to 2 and each chain
entry now records the version its body was hashed under. Recorded rather than
guessed: trying each version until one matched would let an attacker pick the
serialisation that ignores the field they changed. The append-only trigger means
the recorded version cannot be walked back either.

Verified against a database built by the *previous* build: it migrates to v4,
its v1-hashed note still verifies, and editing it appends a v2-hashed revision —
both versions in one chain, verify clean.

Knock-on effects, none of them optional:

- `NotePayload` carries both fields and `SERVICE_VERSION` went to 3. Without
  them the desktop recomputes a different body hash and refuses every note. An
  older laptop that sends neither is read as version 1, which is what its notes
  were hashed under.
- Everything that reads notes now reads the *current* one — lists, bins and
  tagging all skip replaced notes. A correction inherits the original's tags so
  it does not drop out of its reports the moment it is edited, but stays
  unprocessed so tagging revisits it: the text changed, so the bins may need to.
- Threads are ordered by when the *original* was written. Correcting last
  month's note must not move it to the top of today.
- A note can be corrected once. Two corrections of the same note would fork the
  thread, leaving no single answer to what it says now.

**A regression the same slice introduced, found by asking what happens next.**
`tags_needing_review` never learned about `supersedes`, so `counselog review`
offered the same tag twice — once on the corrected note and once on the version
it replaced, which is no longer in the record. Filtered. It was the only read of
a note that had been missed, and it hid because the query selects `FROM
note_tags`, so a grep for `FROM notes` walked straight past it.

**A migration test was quietly lying.** It rewound the schema but left bodies
hashed under the current rules, so it asserted something no older database ever
contained — and would have hidden whether a genuinely old record survives coming
forward, which is the only thing that matters for a database already holding
notes. It now rewrites the chain under version 1 as part of rewinding.

Also learned: SQLite refuses `DROP COLUMN` on a trailing column whose definition
is preceded by a comment block — the edit leaves a dangling comma. Only the test
helper drops columns, but both new columns are placed off the end of their
tables so it stays possible.

**Slice 4 — checking the record from the browser ✅**
`web/views/verify.py`, `verify.html`. `models.verify` has existed since phase 2
and was reachable only from the CLI. The page repeats the limits the CLI states,
in the same words: it shows the notes have not been changed, not that what they
say is true, and not when the events happened. A tool that lets a reassuring
result imply more than it checked is worse than one that checks nothing, because
it will be believed.

Every break is listed rather than the first, a note that was never recorded
through Counselog is called out as such, and a cleared note is reported as no
longer checkable rather than quietly passing.

Also shows the chain head, which was not in the plan. It is the value worth
keeping somewhere other than this machine: a rewrite of the whole chain is
internally consistent and verifies clean, so only an older copy of that value
contradicts it. Phase 7 signs it; writing it down is the poor version of the
same idea, and costs one line to offer.

Part 3 is complete.

### Part 3, slice 5 — who decided a note belongs in a bin ✅ (schema version 5)

`core/tags.py` (extracted from `models.py` first, unchanged, as its own commit),
`note_tags.decided_by` and `note_tags.decision`, `TagDecision`, `carry_forward`.

**Decided: a corrected note is always re-sorted.** The machine's time is what it
is there for, and slow local inference is the trade being made deliberately
rather than a cost to design around. Already the behaviour, so the decision
needed no code — but it is what made everything below necessary rather than
tidy, because sorting now runs often enough to trample a person's judgment
weekly instead of never.

Every row now records who put the note in the bin — a name matched literally,
the model guessed, or a person decided — and whether the answer was yes or no.
Re-sorting replaces only the alias and model rows. A person's answer is left
alone in both directions: a confirmed tag is not handed back to the model, and a
rejected bin is not quietly reinstated. The model may suggest it again; it may
not overrule the answer it already got.

**A rejection is recorded rather than deleted.** `reject_tag` used to delete the
row, which said nothing at all — so the next sorting run was free to suggest the
same bin, and the same answer had to be given again every time.

**`confirm_tag` stopped writing 1.0.** A number where a decision belongs cannot
be told apart from a model that happened to sound certain, which is exactly why
confirmations made before this cannot be recovered by the migration. They come
forward as the model's, and the migration test says so rather than pretending
otherwise. Exact matches *can* be recovered exactly, because a NULL confidence
has always meant a name matched literally.

**What this buys the reports.** A digest can now say how much of what it stands
on a person actually checked. `TagDecision.checked` is deliberately true only
for a human decision — an exact name match is reliable, but nobody read it, and
a report that conflated the two would be overstating itself.

### Part 4 — reports + dashboard ✅

`core/reports.py`, `web/views/reports.py`, `reports.html` and `digest.html`. Two
pages: the per-person digest, and a dashboard of how recently each person has
been written about. No schema change — everything either page needs was already
in the record.

**It is `core/reports.py`, not `desktop/reporter.py` as planned.** The plan put
the reporter on the desktop because that is where the model lives, and there is
no model in this. A digest is a read of the laptop's own record — a join, a
sort, and some whitespace — so building it on the desktop would mean shipping
notes across a machine boundary to do work that is already sitting on top of the
data. `core/` is right because both machines may legitimately assemble one.

**Chronology means when it happened, not when it was typed.** A backdated note
sits at `backdated_at`, marked as such. A corrected note sits where the
*original* was written, showing its current text — correcting last month's note
must not move it to the top of today. The notes list already ordered threads
that way; a report that disagreed would have people reading two orders of the
same events.

**`tidy` may change spacing and never a word.** Trailing spaces go, a run of
blank lines becomes one, and `*` and `+` bullets become `-`, so a digest of
notes written across three months does not read as three documents. A bullet is
only recognised with a space after the marker, which keeps `*emphasis*` and
`2 + 2` out of it. It is idempotent by construction and tested as such: a
cleanup that keeps changing its own output means two readers of one note can see
different text (Law 7). The page says it tidies spacing and that the words are
as written, with every note one tap from its own page to check against.

**The digest counts three kinds of answer separately** — a person checked it, a
name matched exactly, or the model guessed — because they are not the same
quality of fact. Each note carries its own marker where it sits, guesses
included. Nothing is omitted for being unchecked: leaving those out is what
would make the page look better checked than it is, and this is a document
someone may carry into a difficult conversation. A cleared note appears too, as
having existed, since dropping it silently would understate what was written.

**A range it cannot read shows nothing rather than something else.** Dates come
in as `YYYY-MM-DD` only — `date.fromisoformat` also accepts `20260301` and week
dates, and someone who typed one and got a different range would have no way to
tell (Law 5). A backwards range is refused for the same reason: a digest headed
"June to January" and showing nothing looks exactly like a person nobody has
written about, and those want very different reactions. The form keeps what was
typed while it complains, and is a GET, so the range you are reading is in the
address and can be kept.

Both ends are whole days. The end of a day is spelled `T23:59:59.999999`, which
works because `.` sorts above the `+` that opens a timezone offset — so a note
at `23:59:59+00:00` on the last day is inside the range and one at `00:00:00`
the next morning is not. Text comparison, the way every other date filter in the
record already works.

**The dashboard is ordered by silence, not by name.** Longest gap first, with
anyone who has nothing written about them at the top. Sorted alphabetically it
would tell you who is on your list, which you already know; sorted this way the
person you have not written about since March is where you will see them. It
also declares how many notes are not sorted into any bin yet — without that, an
empty digest reads as "nothing was ever written" when it means "nothing has been
sorted".

Two smaller findings. A gap can be unknown for two different reasons — nothing
written, or a `backdated_at` that will not parse, which the schema permits — and
the page says which rather than folding both into one phrase. And people who
have left the team keep their line, in their own section: their notes are still
in the record and still readable, so their count is still true.

**LLM polish is not built.** The plan had it behind an explicit `--polish`;
there is no CLI here to carry a flag, and as a button it is a slice of its own —
a report endpoint on the desktop, a prompt, a schema constraint, and a session
handshake, all to produce text that reads like the record but is not it. Spec §9
asks for a digest with no synthesis and defers narrative drafting until there is
real note history to design against, so nothing is missing from the MVP. It is
in the backlog below with what it would cost.

**Found by playtesting, not by the tests.** Four faults, none of which any test
was going to catch, because each needed either a real record or a real screen.

The record they were built against had every note *unsorted* — three notes,
edited, so all three were queued for re-sorting and none was in a bin. That is
the state the tests never posed, and it broke two things at once:

  - The digest rendered **"What this is built on" with nothing under it**, a
    heading announcing a summary that did not exist. The `<h2>` sat outside the
    check for whether there were any counts.
  - The dashboard said **"1 note has not been sorted, so it is in none of these
    digests" about a note that was plainly on a digest page**. `unsorted_count`
    was `unprocessed_notes`, and a corrected note is queued for sorting again
    *and* carries the original's bins forward. The sentence claims "in no bin",
    so it now counts notes with no included tag — the thing it actually says.
    This one is the worst of the four: a page confidently telling the reader
    something false about its own completeness.

The other two came from looking at the page at phone width, which is where it
will mostly be read:

  - Two full-width date fields and a button **buried the notes below the fold**.
    Side by side was tried first and does not work — a native date field is
    nearly half a phone screen wide on its own — so the range is now a
    `<details>`, folded away, and opened whenever a range is in force or a date
    was refused. Folded, its summary names the range being shown, so notes are
    never missing without the page saying why. No script, and still keyboard
    and screen-reader operable.
  - **"Show everything" split across two lines**, reading as two separate
    links. `a.cancel` no longer wraps.

Method, for the next time: the real record for the empty states, and a seeded
fictitious one under `COUNSELOG_HOME` for the populated ones, driven with curl
and screenshotted headless at 390px. The real record was never written to.

Cleanup: `decision_for` was a helper copied inside `tests/test_tag_provenance.py`
and is now `tags.decision_for`, where the report needed it too.

Part 4 is complete, and with it phase 6. Everything left before hardening needs
the laptop and the key in it.

### Re-measuring binning on new hardware (2026-10-21) 🟨

The desktop now has a Radeon VII (16 GB) and a llama.cpp router beside Ollama.
`bench/` can ask either (`--backend`), and gained a 32-note PMO test set
(`bench/data/pmo_notes.md`, fictitious, generated outside the project), a
logprob classifier, and a Laya run in its own venv. Numbers and caveats are in
`bench/README.md`; the short version:

- **gemma4 12b on llama.cpp is ~50x faster than the shipping default** and no
  less accurate on what we can measure: 68/70 at under 2 s a note, against
  deepseek-r1:14b's 100–215 s on Ollama.
- **No method yet makes review catch the mistakes that matter.** gemma is
  confidently wrong; Laya is honestly uncertain but misses plain cases.
- **Update 2026-10-22, with 50 more notes (14 firm yeses in 88):** every
  method finds only about half the notes that belong in self or team. The
  earlier near-perfect scores came from a set with almost no positives. A
  missed bin makes no tag, so review never sees it — which makes the backlog's
  "labels only exist where the model said yes" a product problem, not just a
  training one: the self and team bins are silently half empty.

Nothing in `desktop/tagger.py` has changed. Moving it to llama.cpp is a backend
setting in `core/config` and a second request builder, and waits on the above.

Open: the three ARGUABLE labels in `bench/pmo.py` (07-21, 07-23, 09-19) and
09-23 ("thanked the whole team" — firm "neither", but every model says team).

### Backlog — wanted, not scheduled

Raised while playtesting; recorded so they are not rediscovered later.

- **Offline spelling and grammar help.** Wanted more once editing means a
  permanent revision rather than a silent fix. Must not be the browser's, for
  the reason above. The local model could do it, but that is a slow round trip
  for a typo, so this needs thought rather than an obvious answer.
- **Reprocessing on much weaker hardware.** Re-sorting every correction is a
  deliberate trade: local inference is slow (deepseek-r1:14b measured at ~88 s a
  note) and the machine's time is what it is for. Someone running this on a
  laptop that struggles would want the choice, which means the policy wants to
  stay in one obvious place rather than spread across the edit path.
- **File ingest in the browser.** `counselog import` already exists in the CLI,
  one file to one note, with `--third-party` setting `source_trust` so the
  stronger sanitization of spec §10 can be applied later. The browser has no
  equivalent. Note that spec §7 deliberately scoped sanitization to
  self-authored text; a file arriving from elsewhere is the case that scoping
  was deferring, so this is not purely an interface job.
- **A polished digest.** A digest read aloud is a wall of raw notes. Having the
  local model smooth it would need a report endpoint on the desktop, a prompt, a
  schema-constrained response and the session handshake that hands over the DEK
  — and then a page that makes unmistakably clear which words are the record's
  and which are the model's, because the whole value of the digest is that it is
  the former. Worth doing once there are enough notes to judge whether the raw
  version is actually hard to read.
- **"No bin matched" still cannot be told from "the model changed its mind."**
  Much narrower since the note-first fix (see phase 4 below), but not gone: an
  empty answer prints the same line whether the model considered the note and
  declined it or simply answered differently this time. The model does return a
  confidence on its "no" — `self: false` at 0.8 — and nothing records or shows
  it. Cheap to improve whenever the tagging output is next touched.
- **Digests for the `self` and `team` bins.** Notes sort into three kinds of
  bin, and only the per-person one has a page. §9 asks for exactly one report,
  so this is scope rather than an oversight — `core/reports` already works on
  any bin key, so it is a route and a heading when it is wanted.

- **Clues the notes leave about how to read them.** The PMO expansion set
  (2026-10-22) showed notes carrying instructions for their own processing,
  written by the supervisor to their future self. Each is a feature someone
  will want, and each is a way the tool could misread its own record:
  - *Follow-ups.* Nearly every note ends with one, and they are action items
    with an owner (the writer) and often a date ("Revisit with Sam Friday Oct
    23"). A digest that cannot tell an open follow-up from a closed one is
    missing the part a supervisor rereads most.
  - *Requests for analysis.* "I write more words about people when I'm worried
    about them … I want whatever this tool becomes to help me see that." Note
    length and sentiment per person, over time, is the first analysis worth
    building — and the length half needs no model at all: it is a count over
    the record, deterministic and cheap (Law 7, Guideline 3).
  - *Self-observations about bias.* "Reviewing these notes it's like 70%
    problems. That's not a true picture of anyone." A report that surfaces this
    pattern helps the record be fair; one that only summarises would amplify it.
  - *Privacy markers.* Three entries say `Visibility: Private`. **Decided
    2026-10-22: no extra privacy tier.** Counselog is eyes-only already; a
    second level inside it would be a promise about who reads which note that
    nothing else in the design is built to keep. A marker like this is note
    text and stays note text.

- **A production instance beside a development one.** Raised 2026-10-22. So
  far the running copy has been a test bed with no real notes, so a restart or
  a schema change loses nothing. Once real notes go in, the real record wants
  a copy of its own on this machine, and this folder stays for development.
  What exists, and what is in the way:
  - *Three locations, three overrides.* Data (keyring, databases, spool) goes
    to `COUNSELOG_HOME`, by default `~/.local/share/counselog`
    (`core/paths.py`). Settings come from `COUNSELOG_ENV_FILE`, by default the
    `.env` in the checkout (`core/config.py`). Certificates come from
    `COUNSELOG_CERTS`, by default `certs/` in the checkout (`core/certs.py`).
    Settings and certificates already follow the checkout. **Data does not:**
    every checkout shares the one default home, so today a development copy
    and a production copy would open the same record.
  - *`COUNSELOG_HOME` cannot go in `.env`.* `load_env()` runs only when a
    network setting is first read, so a home set in `.env` takes effect only
    if a network setting happens to be read before the first path. That
    depends on the command, which is exactly what Law 7 forbids. Fix it
    before relying on it: load `.env` once at startup in each entry point, or
    make `counselog_home()` load it too.
  - *Production as its own checkout*, of a tagged commit with its own `.venv`,
    so editing this folder never changes the code that holds the record. It
    keeps the default home. Development gets a home inside this folder
    (gitignored), so its schema can run ahead: migrations only go forward,
    and a newer database refuses to open in an older build.
  - *Separate certificate authorities.* If each instance runs its own CA, a
    development client cannot reach the production service at all. This is
    mutual TLS doing the job it already does, not a new check. They also
    need different ports.
  - *Say which one it is.* A real note typed into the development copy is
    in the wrong record, and moving it means a tombstone in one record and
    a re-entry in the other. The web pages and the CLI should name the
    instance when it is not production (Guideline 2). A step further: a git
    working tree could refuse the default home unless told to use it.
  - *The services.* `deploy/install-user-services` (2026-10-23) installs
    `counselog-web` and `counselog-desktop` as user units for whichever
    checkout runs it, and running it from another checkout repoints them.
    A second instance needs its own unit names, data folder and port, so
    the script will need an instance name.
  - *The YubiKey.* Both instances would ask the same key. Decide whether
    development unlocks by password only, or gets a slot of its own.

- **Learning from review.** Every review is already a labelled example:
  `note_tags` rows with `decided_by = 'person'` and `decision` included or
  excluded. Three levels, cheapest first, and none worth building until there
  are real reviewed notes to fit:
  1. *Calibration.* One temperature per question, fitted to past decisions so
     that a confidence of 0.9 is right nine times in ten — the step Laya's card
     says fixes its overconfidence, and it would tune gemma's logprobs the same
     way. Plain arithmetic, no dependency, and it is what makes
     `DEFAULT_THRESHOLD` mean something. A few dozen reviewed decisions.
  2. *Examples in the prompt.* Show the model a handful of the owner's past
     decisions with each new note. No training; costs prompt length.
  3. *Fine-tuning.* Where Laya's accuracy jumps (0.36 → 0.77 on its own
     benchmark). Hundreds of examples, and PyTorch in something that ships —
     a Law 9 decision, not a bench one.

  Two things have to be settled first:
  - ✅ *Settled by the safety net, part 1 (schema 8).* **Review currently destroys the data calibration needs.** `confirm_tag`
    and `reject_tag` set `confidence` to NULL (`core/tags.py`), on purpose, so
    a decision cannot be mistaken for a guess. But that discards the model's
    number at exactly the moment it acquires a right answer to be scored
    against. The fix is to keep the guess beside the decision — a column or a
    history table, a schema migration either way — not to stop clearing it.
  - **Labels only exist where the model said yes.** A no makes no tag, so it is
    never reviewed, so a miss never becomes an example. Anything trained on
    review alone learns from a biased sample. Some way to look at untagged
    notes is needed, or the misses stay invisible to training as well as to
    the reader.

  And one constraint on all of it: **trained weights are sensitive data.** A
  model fitted to the notes encodes something about them, so it needs the
  DEK's protection — encrypted at rest, never left readable on the desktop,
  whose mirror is meant to be inert ciphertext after a reboot. A handful of
  temperatures (level 1) say little; fine-tuned weights (level 3) say much
  more. Training is local only: Laya's own notebook runs on Kaggle, which
  would send the notes off the machine (Law 2).

### Found while sorting a real record: `tag` could only be the laptop

`counselog tag` and `counselog sync` always presented the `laptop` certificate,
and `certs prune` deliberately deletes every other device's key from the machine
it runs on. So on the machine that holds the record *and* runs the service,
sorting could not be run at all — the only identity available there is the one
enrolled for it, and neither command would use it. `doctor` already had
`--device`; these two now do too, defaulting to `laptop` so nothing changes for
the laptop itself.

Worth keeping in mind for phase 8: the two-machine split is real, but a single
machine playing both roles is the normal development case, and a command that
can only be one of the roles will keep hitting this.

### Phase 4, revisited: the tagging instability, fixed

The model's answer depended on where the note sat in a run. Cause: every request
carried the instructions first, so consecutive prompts shared a long identical
prefix, the runtime reused the cached state for it, and a request that hit the
cache did far less work than one that missed — different arithmetic, and at
temperature zero a near-tie falls the other way.

The note now goes first, so consecutive requests share nothing and each is
processed the same way whatever its position. Measured 2026-09-04 on
deepseek-r1:14b, six hand-labelled notes plus a repeat of the first:

| | labelled set | first note, asked again at the end |
|---|---|---|
| instructions first (old) | 6/6 | flipped to neither — unstable |
| note first (now) | 6/6 | unchanged — stable |

Reproduced twice, both times. No accuracy cost and no extra time; `keep_alive: 0`
also fixes it and costs roughly double per note, so it is the fallback if a
future runtime caches differently.

**Why this mattered more than it looked.** The old ordering scored 6/6 on a fresh
run and only failed on a *repeat* ask — which is the case this design hits most,
because every correction re-queues its note for sorting. The notes most likely to
be re-asked are the ones someone cared enough to fix.

`tests/test_tagging.py` guards the ordering, because it reads like a style choice
and reverting it reintroduces a bug that only shows from the second note onwards.

### Found in use: "the details are in the service log" ✅ *(schema version 7)*

`core/problems.py`, `web/views/problems.py`, `problems.html`, schema version 7.

The 500 page said to check the service log. For the person this is built for
that is a dead end — they do not know where the log is, and should not have to
read a traceback to learn a page broke. But the traceback cannot go to them
either: an exception message can carry a file path or a piece of a note, and
note text does not belong anywhere the encryption does not reach.

**A log tab was the obvious answer and is the wrong one.** The log is the one
thing outside the encryption boundary — everything else the browser shows comes
out of SQLCipher. Rendering it would also undo, one click later, the existing
decision that the 500 page never echoes an internal message. So the two halves
are split instead:

  - a **reference** on the error page, written beside the traceback in the log:
    quotable by someone who cannot read the log, findable by someone who can;
  - a **record** in the encrypted database of when, which page, and the
    exception's class name — never the message, the traceback, or the path with
    its query string. Same shape as `spool_quarantine`, and the same reasoning.

Recording is best effort and cannot make things worse: if the notes are locked
the page says so and points at the log, and a failure inside the handler is
caught, because an error handler that raises leaves the browser with no page at
all. Old problems are dropped past 200 so a crash loop cannot grow the database.

**A defect in the first version of this, found by breaking a page and reading
the log rather than by a test.** The reference was logged against Flask's
`InternalServerError` wrapper, whose traceback stops inside Flask's own dispatch
— so the reference named a line that could not answer the question it exists to
answer, while the real traceback sat in a separate entry with no reference on
it. Now logged against the original exception, and a test checks the line
carrying the reference also carries the fault.

**What caused the report in the first place is worth recording too.** The
service had been running since before phase 7, so it held the old Python while
Jinja loaded the *new* template from disk on first render — the template asked
for a `coverage` variable the old view never passed. Editing templates under a
running service is enough to break it. The 500 was the right behaviour: had
Jinja rendered the missing variable as empty, the page would have quietly
dropped its "who vouched for this" section and looked fully checked.

## Phase 7 — PIV signing *(laptop)* ✅

`core/crypto/signing.py`, `core/signatures.py`, schema version 6.

### Part 1 — the signing core ✅ *(built on the desktop)*

Built the way phase 1 was: a `Signer` protocol with `SoftwareSigner` holding a
key in memory, so every line except the hardware custody is exercised by tests
here. `PivSigner` is written from the documented API and is **unverified** until
the laptop, exactly as `_hardware_responder` was through phase 1.

**A signature covers three fields, not one.** The `entry_hash` alone would be a
signature that could be lifted onto another position and claim to cover a
different amount of the record, so `seq` is inside it. `signed_at` is inside too,
which is the only thing that makes the recorded time worth reading — it cannot
be edited afterwards without breaking the signature. All length-prefixed, and
carrying a version, for the reasons the chain already does both.

**Phase 2's `signatures` table was created early to avoid a migration, and still
needed one.** A signature cannot be checked without the public key, and there
was nowhere to put one. Schema version 6 adds `signing_keys`, so a copy of the
database can be verified by someone holding nothing else. Both tables are
append-only: editing a signature would re-point an attestation at a record it
never covered, and deleting a key leaves its signatures unverifiable — which
destroys the evidence rather than the claim.

**Coverage is the thing a reader gets wrong.** A valid signature is not a signed
record: it covers the chain as it stood when it was made, and every note since
is vouched for by nobody. `verify_coverage` reports how far the newest *valid*
signature reaches, and an invalid one covers nothing — counting it would be the
same mistake as trusting it.

The three failure kinds are kept apart because they mean different things: a
signature over a position not in the chain is a broken record, one made by a key
the record no longer holds is unverifiable rather than wrong, and one that does
not match is the case everyone imagines and the rarest.

Tested against the attack the chain alone cannot catch — rebuild the chain and
it verifies clean, because it is internally consistent; the signature is what
contradicts it. The tests drop the append-only triggers first, because someone
holding the key can, which is why the triggers were never the real defence.

### Part 2 — signing, and saying what is covered ✅ *(hardware still unrun)*

`laptop/sign_cli.py`, `verify` in both interfaces.

**`counselog sign` offers no software alternative, and that is the feature.** A
signing key kept on disk could be used by anyone who can already open the
database, so a signature made with one proves nothing the reader did not already
have — a reassuring row that means nothing is worse than no row. The signer is
built through `build_signer` so tests can substitute one, the same injection
phase 1 used for factors; it is what lets everything but the custody be
exercised on a machine with no key.

**`verify` now answers two questions, always together.** Whether the record was
altered, and who stood behind it. A clean chain nobody has signed is a record
with no author, and reporting only the first half is exactly how that comes to
be read as fully checked. The unsigned case says so in words rather than by
omitting a section.

Both interfaces state the limit in the same sentence, word for word: a signature
says whoever held the key stood behind the record at that moment, and nothing
else. Two interfaces describing one guarantee differently is how a reader ends
up believing whichever version claimed more.

### Part 3 — the signing call was wrong, and reading the source found it ✅

`PivSigner.sign` hashed the payload here and passed `Prehashed` as the *padding*
argument. Padding is read only for RSA; for an EC key the library looks for
`Prehashed` on the **hash algorithm**. So the card would have been handed a
digest and told to hash it — signing `SHA256(SHA256(payload))`, which nothing
could verify. `sign_head` checks its own work before storing, so it would have
refused rather than recorded something worthless, but `counselog sign` would
simply never have worked.

Found by downloading the `yubikey-manager` 5.9.2 wheel and reading
`yubikit/piv.py`, with no key attached. The corrected call is the one `ykman`'s
own `check_key` makes: the message goes in whole with `hashes.SHA256()`, and the
signature verifies with `ec.ECDSA(SHA256)` over that message — which is exactly
what `verify_signature` already did.

**The tests now drive a fake card that behaves like the real one**, reproducing
the branch in `_pad_message` rather than agreeing with whatever it is passed. A
permissive mock would have accepted the broken call happily; this one signs what
the card would sign, so a wrong call fails here the way it would fail on the
key. It asserts the slot is 9c, the curve is P-256, and the PIN is verified
every time. Confirmed by reintroducing the bug and watching three tests fail.

The lazy import means `yubikit.piv` is not available on a desktop, so the test
injects a stub carrying the real constants — 0x9C and 0x11, read out of the same
source.

### Part 4 — signing a record on a machine that does not hold it ✅

`core/detached.py`, `signatures.{request_for_head,sign_request,attach}`,
`counselog sign-request | sign-offline | sign-attach`.

Prompted by a hardware fact rather than a design review: the YubiKey is USB-C and
the desktop holding the record has no USB-C port. The fix is better than the
thing it works around. **Signing never touches note text** — it needs the chain
position and the head's hash — so the key never has to be on the machine holding
the notes, and a machine holding both is a machine where one compromise takes
everything.

Three files, three steps, and only a hash travels: the same value `/verify`
already tells you to write down somewhere other than that machine.

Both files cross a machine boundary, possibly on a USB stick, so they are
untrusted input on the way back: exact format marker, exact version, a position
that is a position, a hash that is 64 lowercase hex, base64 that decodes, and a
size cap before parsing. A signature is then checked against the chain *before*
it is stored — the position must exist, the hash there must be the one signed,
and the signature must verify. Storing an unverifiable row would report tampering
on every check from then on, which is a permanent false alarm.

Attaching the same file twice is refused rather than duplicated, because these
files are carried by hand and that will happen. Two different keys signing the
same position is not a duplicate and is allowed — a second device vouching is
normal.

### Part 5 — the slot was a decoration ✅

Found the moment a real key was set up: the manager GUI generates into slot **9a**
by default, and `PivSigner.slot` was a field that looked configurable and was
ignored — every call reached for 9c regardless. A parameter that quietly does
nothing is worse than not offering one, because it invites someone to set it and
believe it took effect.

The slot is now honoured, `--slot` is on `sign` and `sign-offline`, and the
difference is stated rather than buried: 9c asks for the PIN on every operation,
9a once per session. Both are on-device and non-extractable; only the PIN policy
differs, and SECURITY.md now says which slot its claim belongs to.

### Part 6 — the first signature by a key that cannot be copied ✅

2026-10-21. The custody claim is no longer untested. The key was generated on
the YubiKey, which never touched the desktop holding the record: `sign-request`
here, `sign-offline` on the laptop, `sign-attach` back here, the two files
carried by hand and kept outside the repo. `verify` then reported:

    All 5 notes are unaltered since they were written.
    Signed up to entry 5 of 5.

That is part 4's design working as intended, end to end, on real hardware —
only a hash crossed between the machines.

Noticed while reading that output: `verify` says *how far* the record is signed
but not *by which key*. With one key that is the same thing; once a second
device signs (allowed, by design), "signed" alone stops answering "by whom".
Small, and recorded rather than done.

### Laptop setup checklist

A `Projects/` subfolder is ready on the laptop and `swig` is installed
(2026-08-30). Remaining, before `pip install -e ".[yubikey]"` will work:

| Need | Why | Status |
|---|---|---|
| `swig` | generates pyscard's bindings at build time | ✅ done |
| `libpcsclite-dev` | PC/SC headers; the build fails without them even with swig | ⬜ |
| `pcscd` | smartcard daemon; runtime requirement for PIV (phase 7) | ⬜ |
| udev rules | non-root access to the key over HID and CCID | ⬜ |

**PEP 668 changes the shape of this.** A current Ubuntu marks the system Python
externally managed, so `pip install` into it is refused — correctly. Two
compliant routes, and the second avoids the build toolchain entirely:

    # A: a venv of its own, pyscard built from sdist
    python3 -m venv .venv
    .venv/bin/pip install -e ".[yubikey]"      # needs swig, libpcsclite-dev, python3-dev

    # B: let the distro provide the smartcard stack
    sudo apt install yubikey-manager           # python3-ykman, python3-pyscard, pcscd, udev
    python3 -m venv --system-site-packages .venv
    .venv/bin/pip install -e .                 # no extra: the venv can see the system ykman

B installs 5.8.0 where PyPI has 5.9.2. Checked rather than assumed, since phase 7
part 3 was written against the 5.9.2 source: `_pad_message` is byte-identical
between them, `PivSession.sign` has the same signature, `list_all_devices` the
same return shape, and `SLOT.SIGNATURE` and `KEY_TYPE.ECCP256` the same values.
The extra's pin is now `>=5.8` to match what was verified.

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

## The safety net: checking the sorting ✅ *(scoped 2026-10-22; done 2026-10-23)*

**Why.** Measured on 88 notes, every model finds only about half of what belongs
in `self` or `team` (`bench/README.md`). A missed bin makes no tag, and review
today only ever shows *tags*, so a miss is invisible: the bins are silently half
empty and nothing in the interface says so. The same blindness is why the
backlog says training would learn from a biased sample. One feature fixes both,
which is why it comes before any trainer: the trainer's data *is* this feature's
output.

**What exists, and what it lacks** (read from the code, 2026-10-22):

- `judge_self_team` asks for a confidence on both answers, then keeps only the
  yeses. A confident no and an unsure no are thrown away identically.
- `set_tags` marks the note `processed`. "Sorted into nothing" and "never
  considered" are then the same row — the backlog's "no bin matched cannot be
  told from the model changed its mind", in its general form.
- `confirm_tag` / `reject_tag` NULL the confidence, deliberately, so a decision
  is never mistaken for a guess — and in doing so destroy the model's answer at
  the moment it gains a right answer to be scored against.
- `counselog review` (CLI only) lists unsure *yeses*. The web note page shows
  tags read-only. A below-novice user (Guideline 2) has no way to fix sorting
  in the browser at all.
- "Held for review" is already taken in the web UI by quarantined spool
  entries. This feature needs another name — **"Check the sorting"**.

**Scope — five parts, each shippable on its own, in this order:**

1. **Keep every answer the model gives.** A new append-only table, schema v8:

       model_judgements(note_id, bin_key, said_yes, confidence,
                        model, method, judged_at)

   One row per bin per sorting run, yes *and* no, never updated. `note_tags`
   stays what it is — the current state, which the reports read — so nothing
   that reads it changes. This also settles the backlog item: confirm and
   reject can keep clearing `note_tags.confidence`, because the guess now lives
   here. `model` and `method` (json / logprob / …) are recorded so a later
   calibration fits only the answers it is calibrating. No note text: ids and
   numbers only, inside the encrypted database like everything else.

2. **A queue with three kinds of entry**, computed from the record, nothing
   stored:
   - *In no bin at all.* Processed, no included tag of any kind. The one that
     matters most and the one that does not exist today.
   - *Unsure answers, either way.* A yes **or a no** below the threshold. Only
     possible once part 1 keeps the noes.
   - *An audit sample of confident answers.* A fixed one-in-N of the rest,
     chosen by a keyed hash of the note id so the same notes are sampled every
     time — a stable sample, not a reshuffle each visit (Law 7). This is the
     part that makes the data unbiased: without it, a confident mistake is never
     seen, and calibration and training both inherit the blind spot.

   Anything a person has already answered leaves the queue for that bin.

3. **"Check the sorting" in the browser.** One note at a time, the text, and
   for each of self and team a plain question with two buttons ("Is this about
   you? Yes / No"), the model's answer shown beside it as a suggestion, never
   pre-selected. Plus "Someone named here isn't in a bin", which links to that
   person's page to add the alias — because an alias, once added, fixes every
   past and future note at once and a one-off tag fixes one. Keyboard-operable,
   real `<button>`s, readable without colour (Guideline 5). The notes page gets
   a count: "7 notes are in no bin."

4. **The CLI catches up.** `counselog review` gains the same three kinds, so the
   two interfaces describe one queue — the same rule as `verify`'s wording.

5. **Say how far to trust the bins.** From the audit sample alone: "Of the last
   40 notes checked at random, the sorting missed 6." That is a measurement, it
   is the honest answer to "can I rely on the self bin?", and it is the number
   that tells the owner whether a better model or a trainer is worth it. Shown
   on the digest pages for self and team, and only once the sample is big
   enough to mean something.

### Part 1 — every answer is kept ✅ *(2026-10-22)*

`core/judgements.py`, schema 8, service version 4.

- `judge_self_team` returns both answers, with the confidence exactly as the
  model gave it — None when unusable, never the fallback. The fallback is now
  applied only in `sort_note`, where a yes becomes a tag and needs a number for
  review. Storing the fallback would have recorded 0.5 for answers the model
  never quantified, and anything later fitted to these rows would have learned
  from a number nobody said.
- `/tag` returns `judgements` and `method` beside `tags`. Version 4 is
  *required*: a version 3 desktop sends no answers, and sorting against it
  would quietly go back to losing every no.
- `counselog tag` keeps them after `set_tags`, so a failure loses evidence
  about the model and never a note's place in the reports.
- Nothing is backfilled. A tag is only the yes half of an answer.
- `tagger.METHOD` names the prompt; bump it whenever the prompt, schema or
  request options change, or old and new answers get pooled.

Found on the way, and fixed: every shape check in `core/` matched with a regex
ending `$`, which in Python also accepts a trailing newline — `"team\n"` was a
valid bin key, and a hand-carried signing file could carry a 65-character
hash. Now `fullmatch` throughout (`protocol`, `detached`, `web/views/reports`).
Also: valid JSON of the wrong shape from the model (a list, a string) reached
`.get` and crashed; it is now reported as an unreadable answer.

### Part 2 — the queue ✅ *(2026-10-23)*

`core/checking.py`. `to_check(conn, threshold)` returns the notes worth a
person's look, each with the bins to ask about, why, and what the model said;
`count_in_no_bin(conn)` is the figure for the notes page. Nothing is stored.
Nothing shows it yet; that is parts 3 and 4.

- *In no bin* asks about both `self` and `team`, whatever the model said,
  since a confident no is exactly what left the note there. It leaves the
  queue once a person has answered both. It stays in the count, because the
  note is still in no report.
- *Unsure* is the latest answer below the threshold, or with no number. For
  notes sorted before schema 8, the model's own tag stands in as a yes, so
  nothing `counselog review` showed is lost.
- *Audit* draws one note in `AUDIT_ONE_IN` by a hash of its chain entry,
  labelled and versioned. The draw is fixed for the life of the note and
  independent of the model. A note with no answers on record is not audited:
  there would be nothing to compare against.
- Sorted, current, uncleared notes only. A person's answer (`confirm_tag` /
  `reject_tag`) settles that bin.

Two of the open questions, answered by default so the work could go on. Both
are one constant each to change:
- **N = 10.**
- **An unsure no uses the same threshold as an unsure yes.** A looser one is
  plausible, but there is no measured basis for picking it until part 5
  reports how often the confident noes are wrong.

The third question (offered after each run, or visited) belongs to parts 3–4.

### Part 3 — "Check the sorting" in the browser ✅ *(2026-10-23)*

`/check` (`web/views/checking.py`, `check.html`). It shows one note at a time:
why it is there, the full text, and a fieldset per open bin with a plain
question, the model's answer as a sentence, and two Yes / No buttons. The
buttons are identical apart from their value, and neither is focused or
highlighted; a test pins that. Each answer is its own form, saved at once,
through `confirm_tag` / `reject_tag`. "Not now" passes over a note with
`?after=<id>`, so nothing is stored for it either. Answers are refused for a
bin the model is not asked about, an answer other than yes or no, and a note
that has been replaced or cleared since the page loaded.

The notes page now says "N notes are in no bin, so they appear in no report"
and links here, and its footer links here too.

`REVIEW_THRESHOLD` moved to `core/checking.py`. It is a checking rule, and the
web pages apply it; `desktop.tagger.DEFAULT_THRESHOLD` now points at it.

**Corrected from the scope:** it said an alias "fixes every past and future
note at once." It does not. `update_person` re-sorts nothing, and `tag` only
sorts unprocessed notes, so a new alias reaches only notes sorted after it is
added. The page says exactly that. Re-matching aliases over sorted notes
needs no model (it is string matching) and would be cheap. It is recorded
here rather than built, because it changes tags the reports read.

### Part 4 — `counselog review` reads the same queue ✅ *(2026-10-23)*

`review` now walks `checking.to_check`, so it shows the same notes, reasons
and questions as the browser. The wording lives in `core/checking.py`
(`QUESTIONS`, `why`, `suggestion`) and both interfaces use it. Each note is
shown in full rather than as a 200-character preview: a judgement about what
a note is about needs the whole note.

**The old prompt defaulted to "y".** Pressing Enter confirmed the model's
guess, which is the answer-by-habit the browser page was built to avoid. Now
there is no default. Enter asks again, `s` skips the note, `q` stops.

`tags.tags_needing_review` is gone, since nothing uses it now. Its tests
moved onto `checking.to_check`, which covers everything it did.

The third open question is answered: **offered, not started.** `counselog
tag` ends with "N note(s) worth checking. Run `counselog review`, or open
Check the sorting in the browser." A run can end at any hour. It says so
once, rather than prompting.

`SECURITY.md`'s known gap is restated as "a bin the model missed is caught
only if someone checks". Misses can be found now, but nothing makes anyone
answer, and a confident miss outside the sample stays unseen.

### Part 5 — how far to trust the bins ✅ *(2026-10-23)*

`core/trust.py`. For each of `self` and `team`, over the most recent
`WINDOW` (40) checked notes in the audit sample, it counts how many the
sorting **missed** (model no, person yes) and how many it **added** wrongly
(model yes, person no). It is shown on the Reports page as a sentence:
"Of the last 40 notes checked at random, the sorting missed 6 that were about
the team." Below `MIN_SAMPLE` (10) only progress is shown.

- **Only the audit sample counts.** Notes in no bin and unsure answers were
  asked about because the model had probably gone wrong. Counting them would
  make it look worse than it is, and the figure would then be the wrong
  number to base a model choice on.
- Only notes with both answers on record count. A pre-schema-8 note has no
  model answer, and a missing tag there might be a no or might be nothing.
- The latest model answer is the one scored, so the figure follows the model
  sorting now.

**Not on the self and team digests, as scoped:** those pages do not exist
(backlog, "Digests for the self and team bins"). When they do, `trust.describe`
is the sentence to put on them.

`judgements.latest_everywhere` and `checking.live_notes` / `audit_sample` are
now shared by the queue and the figure, so both read the same sample.

**Out of scope here:** any training or calibration (the backlog's three levels
build on part 1's table), changing the model, and a privacy tier (decided
against, see the backlog).

**Tests, at minimum:** a no is recorded with its confidence; re-sorting appends
rather than overwrites; a person's answer still beats the model's in
`set_tags`; each queue kind appears and disappears correctly; the audit sample
is identical across runs and changes only when N or the key does; a superseded
note never queues; the trust figure is withheld below the minimum sample; the
v8 migration on a v7 database, with a v7 record's existing tags intact.

**Open questions for the owner:**
- The audit rate N. 1 in 10 is a guess: high enough to fill a sample in a few
  months of notes, low enough not to be a chore.
- Whether an unsure no should use the same threshold as an unsure yes. A missed
  bin is the costlier mistake, which argues for a looser one.
- Whether the queue is offered after each sorting run, or waits to be visited.
  Being offered is more likely to be used; it is also a nag.

## Phase 8 — Harden + docs 🟨

Real two-machine run, docs pass. `SECURITY.md` ✅.

### `SECURITY.md` ✅

Written, and written from the code rather than from memory — every parameter in
it was read out of the source while writing, because a threat model that is
plausible and wrong is worse than none. `CLAUDE.md` has told every contributor
to read this file since phase 0; until now it did not exist.

`tests/test_security_doc.py` keeps the numbers true. Scrypt parameters, session
timeouts, sign-in limits, the device secret size and the signature algorithm are
asserted against the code, so a constant that moves fails the suite instead of
quietly making the document a lie. It also asserts the claims that must never
disappear — what the chain and the signature do *not* prove, and the four gaps
in §8 — because those are the sentences a later tidy-up would remove first.

**One overstatement caught while writing it.** The draft said identity is trusted
only from loopback with the proxy's headers, implying that stops a local process.
It does not, and `web/identity.py` says so in its own comment: nothing at that
layer can tell a forged header from a real one, which is exactly why the
passphrase is the control. Corrected, and a test now fails if that claim comes
back.

**The README was promising slightly more than is true.** "Plain text exists only
in memory" is not true of the service log, where a traceback can carry a note
fragment to disk. Squared with §6 rather than left as a nicer sentence.

**Packaging, done early because it was broken.** `pyproject.toml` declared
`laptop.web` — an empty phase 0 scaffold, now removed — and never declared
`web`, so `pip install .` shipped no browser interface at all. It only ever
worked from a checkout because `./counselogweb` puts the repo on `PYTHONPATH`.
Fixed, along with the package data: templates and the stylesheet are not
importable modules, so without `package-data` an install imports cleanly and
then fails on every page. Verified by building a wheel, installing it somewhere
else, and rendering a template out of it — not by reading the manifest.

**`bench/` holds what measures the code against a real model or record.** Not
tests: they take minutes and need Ollama, so `testpaths` excludes them and they
are not installed. It exists because the scripts that chose the prompt ordering
lived in a temp directory and were lost, leaving numbers in a docstring nobody
could re-derive. `bench/seed_record.py` refuses to write into the real record —
a script that fabricates notes must never be able to fabricate them where the
record is meant to be evidence.

`SECURITY.md` must state plainly what the chain and signature do **not** prove:
the chain shows the record is unaltered, the signature shows who held the key,
neither shows the note is *true*, and neither shows *when* the content was
authored — only when it was signed. Third-party proof of time needs an RFC 3161
authority, which leaks note counts and timing; the format reserves room for
anchor tokens, but v0 does not build it.

Also: recommend a tailscale ACL limiting the service port to the laptop, and
note that a real WSGI server replaces Flask's before this faces anything wider.
