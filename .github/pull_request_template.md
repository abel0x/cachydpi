## What changed

<!-- One or two sentences. Why, not just what. -->

## Verification

<!-- How you know it works: the test you added, the command you ran, the
     output you saw. "Should work" is not verification. -->

## SECURITY.md

`SECURITY.md` documents the privilege model, the config contract, and exactly
which fields reach the log and the metrics socket. It has gone stale before —
it still claimed two capabilities were retained after one was dropped, and that
the metrics socket exposed no addresses while the event buffer was embedding
them.

Tick one:

- [ ] This change touches none of: retained capabilities, the privilege-drop
      sequence, the config contract (required fields, defaults, validation), or
      the fields written to the log or the metrics snapshot.
- [ ] It touches one of those, and `SECURITY.md` is updated in this PR.

> Adding a log field whose value says *where the user connects* — a domain, an
> SNI, a peer address — is covered mechanically: `tests/no_identifying_fields_leak.rs`
> fails unless it goes through `logging::peer()`. The checklist is for the parts
> a test cannot see.
