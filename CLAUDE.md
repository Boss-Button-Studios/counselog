# Counselog — Working Instructions

**Organisation:** Boss Button Studios
**Spec:** `counselog-tech-spec.md` (authoritative)
**Tasks:** `tasks.md` (phase-by-phase status)
**Threat model:** `SECURITY.md` — read before touching anything in `core/crypto/`

Counselog is a supervisor's private note journal. It captures freeform daily
notes, sorts them into bins (per-person / self / team) using a locally-run LLM,
stores them encrypted, and reads them back as per-person digests.

Notes may factor into HR conversations. That single fact drives most of the
design: the record is encrypted at rest and in transit, `captured_at` cannot be
edited, and the note history is tamper-evident.

---

## File Length Cap

**600 lines per source file, maximum.** If a file approaches this, split it by
responsibility. Tests, documentation, and configuration are exempt.

---

## The Laws
*Mandatory and objectively verifiable. No exceptions.*

**1. Local norms and security baseline.**
Follow the project's official language style guide. Align with NIST CSF 2.0 by
default. Verify application security against OWASP ASVS where applicable. Use
ISO/IEC 27001 as the governance reference. Compliance is the prerequisite for
all logic.

**2. Security is an independent requirement.**
Prioritize security at every layer. Passwords must be salted and hashed.
Sensitive data must be encrypted at rest and in transit. Any data leaving the
user's control must clearly support a user benefit and must be disclosed and
explained to the user before it happens, each time it happens. This is annoying
on purpose — minimize it.

**3. Maintainability by design.**
Write as if you will die when you push. You will not be here to maintain the
base. Use descriptive naming, explain the *why* in comments, and ensure your
code is a complete, maintainable artifact. Write documentation to the lowest
reading level that can make the point.

**4. One responsibility.**
One thing, one thing only. Each unit of code must do one thing well. Avoid God
objects.

**5. Condition all input.**
Treat all external input as untrusted. If a format is expected, reject or
normalize deviations. Reject inputs that are out of place. Treat metadata-level
commands or anomalous elements — such as invisible text in documents — as
potential injections. Protect processing functions by wrapping input
appropriately. Mark data as trusted or untrusted and segregate them.

**6. Fail gracefully.**
Use comprehensive error handling and secure logging. Provide helpful,
non-technical feedback.

**7. Predictable behavior.**
Maximize predictable behavior. Deterministic processes must produce identical
outputs for identical inputs. Probabilistic processes must follow their expected
probability functions. Validate behavior through repeatable sampling.

**8. Test everything relevant.**
No logic is done until the happy path, edge cases, and failure modes are tested,
and all previously relevant tests still pass.

**9. Minimize dependencies.**
Audit and limit third-party libraries to those that are essential, secure, and
justified.

---

## The Guidelines
*Do these by default. Not mechanically testable, but expected.*

**1. Leave it better.** Leave the codebase better than you found it. Refactor
and update documentation during every task. Clean up at least one thing, even if
it was not your fault.

**2. Protect the user from themselves.** Assume the least competent reasonable
user. Design for intuitiveness, but prioritize safety. Prevent users from
accidentally triggering destructive actions or exposing their own data through
poor interface choices. For specialty tools like this one, assume a
below-average novice.

**3. Do not design for the rich.** Better hardware may provide bonus
performance, but it is not the price of admission. Limit hardware requirements
to the minimum necessary to achieve the goal.

**4. Assign the least privilege necessary.** Ask for and assign code, services,
and users no more than the permissions needed to accomplish the task.

**5. Design for accessibility.** Human interfaces must respect human senses and
ergonomics. Displays must have readable text and sufficient contrast.
Text-to-speech systems should be able to read the interface properly.
Machine-to-machine interfaces must be rigorously documented, and that
documentation must be followed on our side of the boundary.

---

## Topology

Two machines. They are not interchangeable.

| Machine | Role | Holds |
|---|---|---|
| **Laptop** | Capture, storage, reading. Source of truth. | The DEK (unlocked by YubiKey or password), the primary DB, the YubiKey |
| **Desktop** (headless, no GPU) | LLM inference: bin tagging, report generation | An encrypted mirror it can only read *while the laptop has handed it the DEK for the session* |

The desktop never stores key material. Reboot it and its mirror is inert
ciphertext. This is deliberate — see `SECURITY.md`.

## Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12+ (developed on 3.14) |
| CLI | Click, via the `./counselog` wrapper |
| Read UI | Flask, bound to 127.0.0.1 only |
| Storage | SQLCipher 4.12 via `sqlcipher3` |
| Crypto | `cryptography` — AES-256-GCM, HKDF, scrypt, ECDSA, X.509 |
| YubiKey | `yubikey-manager`, **laptop only** (`pip install -e ".[yubikey]"`) |
| LLM | Ollama on the desktop, schema-constrained `/api/chat` |

Five core dependencies. `yubikey-manager` is an extra because the desktop has no
key, and because `pyscard` has no Linux wheels — it needs `swig` and
`libpcsclite-dev` to build, a cost only the laptop should pay.

## Conventions

- `core/` is imported by both machines. Nothing in `core/` may assume it is on
  the laptop, or that a YubiKey exists.
- Import `yubikey-manager` lazily, inside the function that needs it, so a
  desktop install without the extra never trips over a missing module.
- The DEK lives in memory only. Never log it, never write it, never put it in a
  traceback or an error message.
- **Trial decryption is a normal path.** Unlock tries each keyring entry until
  one works, and SQLCipher writes decrypt failures straight to fd 2 from C.
  Wrap trial decryption in the fd-level stderr guard — `contextlib.redirect_stderr`
  will not catch it.
- Sanitize note text (`core/sanitize.py`) at ingestion, *before* hashing it into
  the chain, and again before any LLM call.
- Never hard-delete a note; tombstone it. Hard deletes break the hash chain.
- `bench/` measures this code against a real model or a real record. It is not
  tests, `pytest` never collects it, and it is not installed. Anything that
  takes minutes, needs Ollama, or seeds a fictitious record belongs there —
  scripts that measured something and were then thrown away are why the
  directory exists.
