# Counselog — Technical Spec (v0 / MVP)

## 1. Purpose

A personal tool for a supervisor to capture freeform daily notes, automatically
sort them into bins (per subordinate, self, team), store them securely, and
later generate reports/dashboards from them using a locally-run LLM.

This spec covers the **MVP scope only**. The goal of the MVP is to get a
working end-to-end loop running so real notes can accumulate — report and
dashboard design beyond the basics is intentionally deferred until there's
real data to design against (see §9).

## 2. Non-Goals (for v0)

- Multi-user / multi-tenant support
- Mobile capture
- Cross-device sync beyond the two machines below (tailnet-based multi-device
  capture is a future extension, not v0)
- Automated sentiment/theme extraction or narrative report generation
- Real-time/streaming dashboards

## 3. Hardware & Topology

| Machine | Spec | Role |
|---|---|---|
| Laptop | i7, 16GB RAM, ~2GB VRAM | Note capture, encrypted local storage, UI/report viewing |
| Headless desktop | No GPU (currently), validated to run 7B–14B models | LLM inference: bin-tagging, report generation |

**Rationale:** the laptop's GPU is too small to meaningfully accelerate a 7B+
model, so it would fall back to CPU regardless — better to keep it as a thin
client. The desktop is the only machine that should load and run the model.

Communication between the two machines happens over the local network (a
tailnet is assumed to be available, trusted, and NOT yet in scope for MVP —
see §7 for transit security).

## 4. Architecture Overview

```
[Laptop]                                   [Headless Desktop]
 ┌─────────────────────┐                    ┌───────────────────────┐
 │ Capture UI           │                    │  LLM runtime           │
 │ (text prompt / file) │                    │  (Ollama or LM Studio) │
 │        │             │                    │        ▲               │
 │        ▼             │                    │        │               │
 │ Timestamp + stage     │   TLS over LAN     │  Bin-tagging service   │
 │        │             │ ─────────────────► │  Report generation     │
 │        ▼             │ ◄───────────────── │        │               │
 │ Encrypted SQLite DB   │   (tagged notes /  │        ▼               │
 │ (notes, bins,         │    report output)  │  Encrypted SQLite DB   │
 │  metadata)            │                    │  (mirror, for          │
 │        │             │                    │   reference/validation)│
 │        ▼             │                    └───────────────────────┘
 │ Report/Dashboard UI   │
 └─────────────────────┘
```

Both machines keep an encrypted-at-rest copy of processed notes. The laptop's
copy is the primary/source-of-truth; the desktop's copy exists so reports can
be regenerated or validated without re-sending notes from the laptop.

## 5. Data Model (laptop, mirrored on desktop)

**`people`**
| column | type | notes |
|---|---|---|
| id | integer PK | |
| display_name | text | e.g. "Sarah K." |
| aliases | text (JSON array) | e.g. `["Sarah", "her", "SK"]` — used for bin resolution |
| active | boolean | soft-delete when someone leaves the team |

**`bins`**
Fixed set for v0: `self`, `team`, plus one row per active person in `people`.
(Modeled as a bin type + optional `people.id` foreign key, rather than a
free-standing table, to keep "self" and "team" from needing fake person rows.)

**`notes`**
| column | type | notes |
|---|---|---|
| id | integer PK | |
| captured_at | timestamp | **set automatically at ingestion, never silently editable** |
| backdated_at | timestamp, nullable | explicit separate field if a note is entered late but describes an earlier event — keeps `captured_at` honest |
| source_type | enum | `text_prompt` \| `file_import` |
| raw_text | blob (encrypted) | the note content |
| processed | boolean | whether bin-tagging has run |

**`note_tags`**
| column | type | notes |
|---|---|---|
| note_id | FK → notes.id | |
| bin_id | FK → bins.id | a single note may map to multiple bins (e.g. mentions two people) |
| confidence | float, nullable | set when tagging is LLM-assisted rather than exact name match |

Keeping `raw_text` and tags in separate tables means re-tagging or
regenerating reports later doesn't require re-entering data.

## 6. Encryption Scheme

**At rest:** both the laptop and desktop SQLite databases are encrypted
(e.g. via SQLCipher — verify current maintenance status before adopting).
Decryption happens only in memory for display or processing; nothing is
written to disk unencrypted.

**Key management:**
- Primary: YubiKey challenge-response derives/unlocks the database key.
- **Multiple keys supported, not just one.** The interface needs a way to
  register more than one physical key against the same database — a lost or
  damaged YubiKey shouldn't mean lost access to encrypted notes. Practically,
  this means the actual database encryption key is not derived directly from
  a single YubiKey's response; instead, the encryption key is wrapped
  (encrypted) separately for each registered key, and any one of them can
  unwrap it. This also implies a "manage keys" UI action: add a new key,
  revoke a lost one (without needing to re-encrypt the whole database,
  ideally — re-wrap just the key-wrapping envelope).
- Fallback: password, for when no registered YubiKey is plugged in — treated
  as one more entry in the same wrapped-key scheme above, not a separate
  mechanism.
- Linux integration path (needs verification against current docs before
  implementation): Secret Service API (`libsecret`/`gnome-keyring` or KDE
  Wallet) for OS-level key storage, with `ykman` or `pam_yubico`-style
  challenge-response for the YubiKey factor, and a wrapped-key scheme (e.g.
  age or a similar current tool — verify what's actively maintained before
  choosing) for the multi-key unlock described above.

**In transit:** TLS between laptop and desktop. Even though the LAN is
currently trusted, this is built in from v0 rather than retrofitted later,
since the plan is to extend capture to other devices over a tailnet.

**Backdating/audit:** because notes may factor into HR conversations,
`captured_at` is immutable after write. Any correction is a new field
(`backdated_at`) or a new note, never an overwrite.

## 7. Note Sanitization

**Threat model for v0:** note content is almost entirely self-authored, so
this is not the "hostile third-party document" case (e.g. someone hiding
instructions in white-on-white PDF text or `display:none` HTML to manipulate
whatever reads the file). The realistic risk is accidental — copy-pasting an
email or a Slack message into a note can drag in invisible Unicode artifacts
(zero-width joiners, BOM characters, directional-override marks) that could
confuse the tagging prompt, not a deliberate attack.

**MVP requirement:** before any note's `raw_text` is sent to the LLM for
bin-tagging or included in a report, strip zero-width/invisible Unicode
characters and non-printable control characters, and normalize to Unicode
NFC. This is dependency-light (no OCR, no document parsing libraries) and
appropriate for the plain-text/markdown note capture that v0 actually
supports.

**Explicitly deferred (see §9):** tiered sanitization for hidden-element
detection and OCR-based rasterization (the kind needed for untrusted
third-party PDFs/DOCX/HTML) is not built for v0, since it solves a threat
that doesn't exist yet given self-authored-only input.

## 8. Sync Protocol (laptop ↔ desktop)

1. Laptop batches unprocessed notes (`processed = false`) and sends `raw_text`
   + `id` over TLS to the desktop's inference service.
2. Desktop runs bin-tagging against the `people` table (synced or passed
   alongside), returns `note_id → [bin_id, confidence]` mappings.
3. Laptop writes tags into `note_tags`, marks note `processed = true`.
4. For report generation: laptop requests a report (bin + date range),
   desktop pulls matching notes from its own encrypted mirror, generates
   output, returns it — no need to re-transmit raw text laptop-side for
   reports on already-synced notes.

Exact request/response schema (REST vs. other) depends on the chosen LLM
runtime's current API — do not hardcode assumed endpoint paths without
checking Ollama/LM Studio's current documentation.

## 9. MVP Feature Cut

Deliberately minimal, to avoid designing reports before real data exists:

- ✅ Text-prompt and file-based note capture, auto-timestamped
- ✅ Bin tagging (self / team / per-person), multi-bin support per note
- ✅ Encrypted storage on both machines, TLS in transit
- ✅ One report: **per-person note digest** — chronological, tagged notes for
  a date range, lightly cleaned up, no synthesis/inference
- ✅ One dashboard metric: **note frequency/recency per person** — a count,
  not an LLM judgment

Explicitly deferred until there's real note history to design against:
sentiment/theme extraction, praise-to-concern ratios, team-level rollups,
narrative report drafting. When these are added, any dashboard built on LLM
inference (as opposed to raw counts) should show which source notes produced
a given trend line, so the read can be checked against the text rather than
trusted blindly.

## 10. Open Questions / Future Work

- Multi-device capture via tailnet (explicitly deferred, but architecture
  above shouldn't preclude it — sync protocol in §8 is written generically
  enough to extend to additional capture devices later)
- Exact confidence threshold for auto-accepting LLM-assisted bin tags vs.
  flagging for manual confirmation
- Whether backdated notes should be visually distinguished in reports
- Retention/deletion policy for notes about someone no longer on the team
- **Key revocation completeness:** removing a lost key's wrapper entry stops
  it from unlocking future access, but does not retroactively protect any
  data if that physical key was already used (e.g. an old unencrypted backup
  made before revocation). True revocation — rotating the underlying database
  key and re-encrypting — is a heavier operation; decide whether "remove the
  wrapper" is sufficient for a lost key, or whether losing a key should always
  trigger a full re-encryption pass.
- **Third-party notes (flagged as a likely near-term development, not
  hypothetical):** if Counselog later ingests documents authored by other
  people — e.g. an employee's written report or self-review, rather than the
  supervisor's own notes about them — the trust assumption behind §7 flips.
  At that point, the full tiered sanitization approach (hidden-element
  detection in HTML/DOCX/PDF, OCR-based rasterization as a "deep" posture for
  suspicious documents) becomes proportionate and should be built before that
  ingestion path ships, not after.

## 11. Assumptions to Verify Before Implementation

- SQLCipher (or chosen encryption-at-rest library) is current and maintained
- Ollama/LM Studio's local API shape and auth model, as of implementation time
- Linux Secret Service / YubiKey integration path for key derivation
