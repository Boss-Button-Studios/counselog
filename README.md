# Counselog

A supervisor's encrypted note journal. Capture freeform daily notes, sort them
into bins (per-person, self, team) with a locally-run LLM, and read them back as
per-person digests.

Your notes are never unencrypted outside the devices you choose. On disk they
are encrypted whole, by a key that is never written down; between machines they
travel over a mutually authenticated, encrypted link; and a note written while
the database is locked is sealed until you unlock it. Plain text exists only in
memory, on a device you decided to let in, while you are looking at it — with one
exception, the service log, where a fault report can carry a fragment of a note
to disk in the clear.

You choose those devices twice over: which machines are on your tailnet at all,
and which browsers you enrol to write notes. Neither is a default.

`SECURITY.md` is the honest version of these two paragraphs: what is protected,
what is not, and what the record does and does not prove. Read it before relying
on any of this. `counselog-tech-spec.md` has the design and `CLAUDE.md` the
working rules.

**Status:** v0, in use as a test bed with no real notes yet. Everything a
person does day to day is in the browser: write a note (locked or not), read
and correct notes, manage people, sort new notes, check the sorting, read a
person's digest, and check the record. Signing needs the YubiKey on the laptop.
`tasks.md` says what is done and what is next.

## Running it

On the desktop, both services run as systemd user units:

    deploy/install-user-services

This installs `counselog-web` (the browser interface, reached through
`tailscale serve`) and `counselog-desktop` (the mirror, and sorting from the
command line with `counselog tag`), pointed at
the checkout the script is run from. Both start at boot and restart if they
fail. Lingering must be on for them to run while you are logged out
(`loginctl enable-linger`). After pulling new code, restart them:

    systemctl --user restart counselog-web counselog-desktop

Restarting the browser interface signs every browser out. That is deliberate:
its session keys exist only in memory.

## No compliance claim

Counselog is not warranted to meet any jurisdiction's legal or regulatory
standards for handling sensitive or personal information. That includes data
protection and privacy law, employment and labour law, and rules on keeping
records about employees. Encryption, a tamper-evident record and the other
protections described in `SECURITY.md` are engineering choices. They are not
a certification, and they do not make any use of this tool lawful where you
are.

If you keep notes about other people with it, you are responsible for knowing
and meeting the rules that apply to you: what you may record, how long you may
keep it, who may see it, and what the people it is about may ask for. Check
with your employer, your HR department or a lawyer. Nothing in this project is
legal advice.

## Licence

MIT, see `LICENSE`. The software is provided as is, without warranty of any
kind.
