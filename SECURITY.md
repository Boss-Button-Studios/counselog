# Counselog — threat model and security notes

Counselog holds a supervisor's private notes about the people they manage. Those
notes may end up in an HR conversation, so two properties matter more than
anything else this program does:

1. **Nobody but the person who wrote them can read them.**
2. **What the record says today is what it said when it was written**, and where
   that cannot be guaranteed, the tool says so rather than implying otherwise.

Everything below exists to serve those two, or to be honest about where they
stop. Read this before changing anything in `core/crypto/`, `core/chain.py`,
`core/spool.py` or `core/signatures.py`.

---

## 1. What is being protected, and from whom

**The asset is the note text**, and after it, the metadata around it: who a note
is about, when it was written, and how often someone is written about. A list of
dates on which a manager wrote about one employee is sensitive even with every
word removed.

The adversaries this is designed against, in the order they are likely:

| Who | What they can do | What stops them |
|---|---|---|
| **Someone who picks up the laptop** | Read files, copy the database | The database is ciphertext from byte 0. Without a registered factor it is noise. |
| **Someone on the same network** | Watch or intercept traffic between the machines | Mutual TLS, both ends pinned to a private CA. Neither end talks to an unauthenticated peer. |
| **Someone who copies the desktop's disk** | Read the mirror | The desktop holds no key. Reboot it and its mirror is inert ciphertext. |
| **The person whose notes these are, later** | Quietly rewrite history to suit a dispute | The hash chain, the append-only triggers, and — once the key is in use — the signature. |
| **A curious process on the same machine** | Set headers, open loopback ports, read logs | Little, at that layer — see §5. A local process *can* forge the proxy's headers, so the passphrase is what actually protects the notes. The log is the weak point, see §6. |

Explicitly **not** in the threat model for v0: a targeted attacker with root on
the laptop while it is unlocked, hardware implants, a hostile Ollama build, or a
compromised `cryptography` package. Any of those wins outright, and pretending
otherwise would be theatre.

---

## 2. The two machines

They are not interchangeable, and the split is a security control rather than a
performance one.

**The laptop** holds the DEK, the primary database, and the YubiKey. It is the
source of truth. Everything else is derived from it.

**The desktop** runs the language model and holds an encrypted mirror it can
only read *while the laptop has lent it the DEK for a session*. It stores no key
material of its own. The lent key lives in memory with a TTL (default 900
seconds, `COUNSELOG_SESSION_TTL`) and is dropped on shutdown, deliberately and
before the process exits rather than as a side effect of exiting.

The consequence worth stating plainly: **the desktop does see note text**, in
memory, during a tagging or sync session. That is the price of local inference,
and it is why the desktop is a machine you own on a network you control rather
than a rented one.

---

## 3. Keys and encryption

**One data encryption key (DEK).** 32 random bytes, generated once, never
written to disk in the clear, never logged, never included in an error message
or traceback.

**The keyring wraps that DEK once per unlock factor.** AES-256-GCM, with the
wrapper's own id and factor name as additional authenticated data, so a wrapper
cannot be swapped between entries. `keyring.json` is written atomically at mode
0600 and contains no secret of its own — only wrapped copies of the DEK.

**Password factor:** scrypt, n = 2^17, r = 8, p = 1, into a 32-byte key
encryption key. Roughly 263 ms and 128 MB per attempt on the reference desktop —
the memory cost is why sign-in is rate limited (§5). Passwords are NFC
normalised before stretching, or the same password typed on a different keyboard
derives a different key. Parameters read back from the keyring are range-checked,
because that file sits outside the encrypted database and is attacker-writable
in the worst case.

**YubiKey factor:** HMAC-SHA1 challenge-response on OTP slot 2, stretched through
HKDF-SHA256 (salt = the challenge, info = `counselog-kek-v1`) to a 32-byte KEK.
HMAC-SHA1 is what the OTP slot offers; the HKDF is what turns a 20-byte response
into a full-width key. This path speaks HID and needs no smartcard stack.

**At rest:** SQLCipher 4.12 keyed directly with the DEK. There is no second layer
of per-column encryption — inside an already-encrypted file it would add
complexity without adding protection. The file has no `SQLite format 3` header;
it is ciphertext from the first byte.

**In transit:** mutual TLS, minimum TLS 1.2, both ends verifying against a
private CA, client certificate required. Each device presents its own
certificate, and `certs prune` exists so the machine that issued them does not
keep everyone else's private key.

**Rotation** re-wraps the DEK and re-keys the database in one operation, refuses
unless every registered factor is present (so a backup key in a drawer is not
silently locked out), copies the old keyring aside first, and reopens the
database with the new key before reporting success. It warns that the old keyring
can still unwrap the old key and should be destroyed.

---

## 4. What the record proves — and what it does not

This is the section to keep honest. Every mechanism below is narrower than it
looks, and a tool that lets a reassuring result imply more than it checked is
worse than one that checks nothing, because it will be believed.

### The hash chain

Every note is hashed into a chain: `entry_hash = SHA256(prev_hash || body_hash)`,
over a canonical, length-prefixed, versioned serialisation of the note. The chain
is append-only at the database level, `captured_at` cannot be edited, and notes
cannot be deleted — only tombstoned, which destroys the text and keeps the
position.

**It proves:** no note in the record has been altered, inserted or removed since
it was written, and verification says exactly where if one has. It also catches a
note inserted directly into the table without a chain entry, which walking the
chain alone would miss.

**It does not prove:**

- that anything a note says is **true**;
- **when the events happened** — only the order in which they were written down;
- **who wrote them.** Anyone holding the key can rebuild the entire chain, and
  the result is internally consistent and verifies clean. Only an older copy of
  the head kept somewhere else, or a signature, contradicts that.

A tombstoned note is reported as no longer checkable rather than quietly passing.

### The signature

ECDSA P-256 over SHA-256, covering a domain-separated, length-prefixed payload of
the format version, the chain position, the head's `entry_hash`, and the time of
signing. On the laptop the key lives in a YubiKey PIV slot: generated on-device
and non-extractable either way. **Slot 9c asks for the PIN on every operation;
slot 9a asks once per session** — 9a is what the manager GUI offers first, and it
works, but "PIN for every signature" is a claim about 9c alone. The public half is
stored in the record, so a copy of the database can be verified by someone
holding nothing else.

**The key does not have to be on the machine holding the notes.** Signing needs
the chain position and the head's hash and never touches note text, so the record
can stay on one machine and the key on another: `sign-request` writes out a
position and a hash, `sign-offline` signs it wherever the key is, `sign-attach`
puts it back. Only a hash crosses, and it is the same hash `/verify` already
tells you to keep somewhere else. This is stronger than keeping both together,
where one compromise takes the notes *and* the ability to vouch for them.

Both carried files are treated as untrusted on the way in. A signature is checked
against the chain before it is stored — the position must exist, the hash there
must be the one that was signed, and the signature must verify — because an
unverifiable row would be reported as tampering every time the record is checked
from then on.

**It proves:** whoever held that key vouched for this record at that moment.

**It does not prove:**

- that the notes are **true**;
- **when the content was authored** — only when it was signed;
- that the *whole* record is covered. A signature covers the chain as it stood.
  Every note written since is vouched for by nobody, which is why both interfaces
  report "signed up to entry N of M" rather than "signed".

An invalid signature covers nothing at all. A signature made by a key the record
no longer holds is reported as unverifiable rather than as wrong, because those
are different problems.

**Third-party proof of time is not built.** Anchoring the head with an RFC 3161
timestamping authority would prove the record existed by a certain moment, but it
leaks note counts and timing to that authority. The format leaves room for anchor
tokens; v0 does not build them.

### Bin tags

A note's bins are not part of the hashed body, so tagging never disturbs the
chain. Each tag records who decided — a name matched literally, the model
guessed, or a person judged — and a person's answer is never overwritten by a
later sorting run. Reports use that to say how much of what they show a human
actually checked, and never count an exact name match as "checked": it is
reliable, but nobody read it.

---

## 5. The browser interface

Two independent gates. A tailscale ACL decides which devices reach the port at
all; the passphrase decides what unlocks the notes. Reaching the page proves
nothing about being allowed to read anything.

- Binds to **127.0.0.1 only**. `tailscale serve` terminates TLS in front of it.
- Identity is taken from the tailscale headers **only** when the request also
  arrives from loopback, since the proxy is the only thing forwarding there.
  **Be clear about what this does not do:** another process on the same machine
  can also reach loopback and set those headers itself, and nothing at this layer
  can tell the difference. It is a check against misconfiguration and stray
  traffic, not against a local attacker — which is exactly why reading notes
  needs the passphrase regardless of who the headers claim to be.
  `--allow-direct` drops even that check for development, and says so loudly at
  startup.
- Session cookie: `HttpOnly`, `SameSite=Strict`, `Secure`. A CSRF token is
  required on every state-changing request — two mechanisms, because SameSite is
  one browser quirk away from being the only one.
- Content-Security-Policy is absolute rather than negotiated: `default-src
  'none'`, scripts and styles from `'self'` only, no `'unsafe-inline'`, no
  framing. The page needs nothing from the internet, so it is allowed nothing.
- Sessions: **5 minutes idle**, refreshed by use, and **30 minutes absolute**.
  The signing secret is regenerated per process, so restarting the service seals
  every session.
- Sign-in is rate limited to protect *memory*, not just guesses: scrypt at these
  parameters costs 128 MB per attempt, so concurrent attempts are capped at 2,
  with 5 attempts per 5 minutes and a 60-second lockout after that.
- The capture textarea sets `spellcheck="false"` deliberately. Chrome's enhanced
  spell check and Edge's Microsoft Editor send what you type to their servers,
  which would break the promise on the front of the README for anyone with that
  setting on.

**Writing while locked.** A note can be written with no key present: it is sealed
to the spool's public key (X25519 to an ephemeral key, AES-256-GCM) and set
aside, then judged at the next sign-in against a hash chain over the spool and a
per-device HMAC. An enrolled browser holds a 32-byte secret in `localStorage` —
so anyone with the unlocked browser can write notes that pass the stamp check,
which is the same trust already implied by holding the device.

Nothing is refused at capture that would cost a note. Bad stamps, unknown
devices and malformed timestamps are all normalised to "unstamped" and held for
review, with the writer told at the time.

---

## 6. Where plaintext exists, and for how long

Being specific about this is more useful than any assurance.

| Where | When | For how long |
|---|---|---|
| Laptop memory | While signed in | Until the idle timeout, lock, or process exit |
| Desktop memory | During a tagging or report session | Until the session TTL expires or the process stops |
| The spool file | A note written while locked | Until the next drain, then the body is cleared in place |
| Spool quarantine | An entry that failed its checks | Kept — its ciphertext is the only copy of what may be a genuine note |
| **The service log** | On an unhandled error | Until you delete it |

**The log is the one thing outside the encryption boundary**, and it is the
weakest point in this design. An exception message or traceback can carry a
filesystem path or a fragment of note text, and the log is plain text on disk
that the DEK does not protect. That is why the error page never echoes an
internal message, why there is no log viewer in the browser, and why the
`problems` table records only a reference, a time, a route name and an exception
class — never the message. Treat the log as sensitive, rotate it, and do not
paste it into a bug report without reading it first.

**Erasure cannot be guaranteed.** `forget` tombstones a note and the spool clears
drained bodies with `PRAGMA secure_delete` and a vacuum, but a copy-on-write
filesystem, an SSD's wear levelling, or any backup taken earlier can keep old
pages alive regardless. Deletion here means "removed from the record", not
"provably gone from the disk".

---

## 7. Running it safely

- **Limit the service port with a tailscale ACL** so only the laptop and the
  devices you actually capture from can reach it. The ACL is the outer gate; do
  not rely on the passphrase alone.
- **Flask's development server is what ships.** It is adequate for one person on
  a private tailnet and is not adequate for anything wider. Put a real WSGI
  server in front before this faces more than that.
- **Back up the keyring**, and register a second factor. With one way in, losing
  it loses every note — there is no recovery path, by design.
- **Keep a copy of the chain head somewhere else.** A rewritten chain is
  internally consistent and verifies clean; an older copy of that value is what
  contradicts it. `/verify` shows the head for exactly this reason.
- **On the laptop**, PIV signing needs `swig`, `libpcsclite-dev`, `pcscd` and
  udev rules. The pip wheel bundles no udev rules, so install the distro
  `yubikey-manager` package alongside it for those.
- **Change the YubiKey's management key and PUK before generating a signing
  key.** Both ship at a documented default, and the management key is what
  authorises key generation and import — left at the default, anyone with brief
  physical access can overwrite your signing key or import one of their own and
  sign as you, which is precisely the property the signature exists to provide.
  `ykman piv access change-management-key --generate --protect` stores a random
  one on the card behind the PIN, so there is nothing extra to keep. The PUK
  matters for the same reason one level down: it can reset a blocked PIN.
- **Generate the slot with `--pin-policy ALWAYS`.** Slot 9c defaults to asking
  for the PIN every time, but stating it means the card enforces what this
  document claims rather than the claim resting on a default.
- **Do not roll back a build past a schema migration** with a database that has
  already been migrated. An older build refuses to open a newer database, which
  is deliberate — it would otherwise read columns it does not understand.

---

## 8. Known gaps

Recorded because a threat model that lists only what is handled is marketing.

- **`PivSigner` has never run against hardware.** It is written from the
  documented API and is unverified until the laptop confirms it.
- **The desktop sees note text in memory** during a session. Local inference has
  no version of this that does not.
- **Tagging is not reproducible.** The model's answer can depend on what was
  asked before it; the prompt ordering fixes the case that was measured, but a
  tag is a suggestion, not a fact, and low-confidence ones are held for review.
- **One user, one record.** No multi-tenancy, no sharing, no roles. Anyone who
  can unlock can do everything.
- **No account recovery.** Deliberate.

---

## 9. Reporting a problem

If you find a security issue in this code, open an issue describing the *class*
of problem without a working exploit, or contact Boss Button Studios directly.
This is a personal tool with a small blast radius, but the data it holds is
somebody's employment record, and that deserves the same care as anything larger.
