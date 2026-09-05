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

**Status:** v0 in development.
