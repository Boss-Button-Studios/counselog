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
| Phase 6 — The browser interface | 🟨 Parts 1–2 done (389 tests, 89% cov) | desktop |
| Phase 7 — PIV signing | ⬜ Not started | **laptop — needs the YubiKey** |
| Phase 8 — Harden + docs | ⬜ Not started | both |

Phases 0–6 are buildable entirely on the desktop. Only phase 7 needs the laptop.

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
the tailnet. Four parts; two are done.

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

### Part 3 — reading back, and the subject registry 🟨

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

**Slice 4 — a verify page ⬜**
`models.verify` already exists and is CLI-only. The page must repeat what the
CLI prints: that this shows the notes are unaltered, not that what they say is
true, nor exactly when the events happened.

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

### Part 3, slice 5 — what a correction does to the sorting ⬜

**Decided: a corrected note is always re-sorted.** The machine's time is what it
is there for, and slow local inference is the trade being made deliberately
rather than a cost to design around. Already the behaviour — `revise` leaves the
correction unprocessed — so nothing was needed for the decision itself. Worth
keeping in one obvious place: a user on much weaker hardware might answer
differently, and that is the line they would want to change.

**But that decision makes tag provenance necessary rather than optional.** Every
correction now re-runs the model, and `set_tags` replaces everything, so today a
typo fix discards a tag you confirmed and can resurrect one you rejected —
`reject_tag` deletes the row, so the rejection is recorded nowhere and the model
is free to suggest it again. Rare enough to ignore when re-tagging was rare;
weekly once corrections are routine.

Proposed: `note_tags` records who decided — alias, model, or person — and
whether the decision was to include or exclude. Re-tagging then replaces only
the alias and model rows and leaves a person's judgment alone, in both
directions. Schema version 5. No protocol change: the desktop already
distinguishes an exact match from a guess by sending a NULL confidence, so
provenance can be settled on the laptop.

### Part 4 — reports + dashboard ⬜

`desktop/reporter.py`, as pages rather than CLI commands.

- Per-person digest: chronological, deterministic cleanup only (whitespace and
  markdown). §9 says no synthesis; Law 7 wants predictable output. LLM polish
  sits behind an explicit `--polish`.
- Backdated notes shown at `backdated_at` with a visible marker.
- Dashboard: note count and days-since-last per person. Pure SQL, no LLM.

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
