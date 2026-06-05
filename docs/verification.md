# The verification model

This is the human-readable contract for the fence between the language model and
the report (`PRD.md` Section 11, AGENTS.md prime directive and Hard rule 4). It
defines two things precisely:

1. the claim-and-citation format the model must emit, and
2. the field-consistency rules the deterministic verifier applies to every claim.

The rule the whole product hangs on: no factual claim reaches a report unless it
resolves to a real, deterministically extracted timeline event by `event_id` and
the facts it asserts (time, principal, action, object) are consistent with that
event. The deterministic layer is the source of truth. The model proposes; the
verifier disposes. The model never decides what is true and never sees raw
evidence files.

Note on style: no em dashes or en dashes anywhere, per PRD Section 15. Use
hyphens, colons, or commas.

## What the model sees

The model is given a compact, id-addressed view of the timeline (FR17), never the
raw evidence. Each event is reduced to its `event_id` plus the addressable fields
the verifier can check against:

```
event_id, datetime, host, principal, action, object, message
```

The `message` is the short normalized summary from the canonical schema, not a
raw artifact. The model never receives `details`, command lines, file contents,
or any source file. This is the structural guarantee in Hard rule 4: because the
model can only address events by id and can only see these reduced fields, it
cannot smuggle a fact in from outside the timeline without the verifier catching
it.

## The claim and citation format

The model returns a single JSON object. Its `claims` field is an ordered array of
claim objects, one per factual statement in the narrative:

```json
{
  "claims": [
    {
      "text": "On WIN-ACCT-07, CORP\\jdoe ran an encoded PowerShell process spawned from Word.",
      "citations": ["6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"],
      "asserts": {
        "datetime": "2026-03-14T08:42:17Z",
        "principal": "CORP\\jdoe",
        "action": "process_create",
        "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      }
    }
  ]
}
```

Each claim object has three parts:

- `text`: the prose that will appear in the report. This is presentation only and
  is never itself checked for truth. It must not assert any fact that is not also
  declared in `asserts` and grounded by a citation.
- `citations`: an array of one or more `event_id` strings. An `event_id` is a
  64-character lowercase SHA-256 hex digest (see `docs/schema.md`). This is the
  only way a claim can point at evidence.
- `asserts`: the machine-checkable facts the claim commits to. Exactly four
  fields are recognized, each optional: `datetime`, `principal`, `action`,
  `object`. These mirror the canonical event fields of the same name. A claim
  must assert at least one of them. Any other key is ignored.
- `revises` (revision rounds only): the `claim_id` of the outstanding claim this
  one replaces, echoed from the revision request (see the loop below). Absent on a
  fresh claim. It is how the engine matches a revision to the claim it fixes
  without relying on ordering.

The `asserts` block is the heart of the fence. The model is not trusted to write
true prose; it is required to commit, in machine-readable form, to the specific
facts it is asserting, so the verifier can check each one against the cited event.
The `text` is bound to those asserted facts: it is the readable rendering of a
claim the evidence actually supports.

### Parsing rules

Claims are parsed deterministically (FR19). The parser is strict about structure
and records every citation, well-formed or not, so the verifier can act on it:

- The output must be valid JSON: either the object form above, or a bare array of
  claim objects. Anything else is unparseable and yields no claims for that round.
- Each citation is classified as well-formed (it matches the `event_id` pattern)
  or malformed (anything else, for example `EVENT-1487` or a truncated hash).
  Malformed citations are retained for the audit log but provide no support: they
  are treated as unsupported (PRD Section 11 step 3).
- A claim that carries no citation at all is rejected.

Because an accepted claim's citations all become links in the report, the verifier
holds every citation to the same standard: a claim is rejected if it carries any
malformed citation, or any well-formed citation that does not resolve to a real
event, even when one other citation does back the assertion. This keeps the
guarantee airtight for multi-citation claims: every citation on an accepted claim
resolves to a real event.

## Field-consistency rules

A claim is **accepted** if and only if all hold:

1. **Citations resolve.** The claim carries at least one citation, no malformed
   citation, and every cited `event_id` resolves to a real event in the
   deterministic store (FR20). A single unresolved or malformed citation rejects
   the claim, so every citation on an accepted claim links to a real event (FR32).
2. **Field consistency.** There exists at least one cited event that is consistent
   with **every** field the claim asserts (FR21). A single event must back the
   whole assertion; this prevents stitching one event's principal onto another
   event's action. Additional cited events are permitted (for example for context)
   but they too must resolve, and at least one must fully back the claim.

If no single cited event satisfies all asserted fields, the claim is **rejected**
with the reason from the first field that fails, checked in this fixed order:
`datetime`, then `principal`, then `action`, then `object`.

### Per-field comparison

Only the fields the claim actually asserts are checked. An absent asserted field
is not checked. A field the event does not have (a null `principal` or `object`)
can never satisfy an assertion about it: you cannot assert a fact the evidence
does not record.

- **datetime** (`time_mismatch`). Both the asserted time and the event time are
  parsed as UTC instants and must agree within a tolerance window. The default
  tolerance is 1 second; it is configurable through `FieldTolerance`. The event
  times are already canonical UTC, and the model is shown the exact `datetime`,
  so the asserted time is expected to echo it. The small default window only
  absorbs sub-second representation differences. An unparseable asserted time is a
  mismatch.
- **principal** (`principal_mismatch`). Compared as text after trimming
  surrounding whitespace and case-folding, because Windows account names are
  case-insensitive. `CORP\\jdoe` and `corp\\JDOE` match; `CORP\\Administrator`
  does not.
- **action** (`action_mismatch`). The canonical snake_case verb, compared after
  trimming and case-folding. The model is shown the exact verb, so it must echo
  it: a claim asserting `process_create` cannot cite a `logon` event.
- **object** (`object_mismatch`). The primary target (process path, file path,
  registry key, remote endpoint), compared after trimming and case-folding, since
  Windows paths are case-insensitive.

### Rejection reasons

Every rejected claim is recorded with one of these reasons (FR22, FR25):

| Reason | Meaning |
| --- | --- |
| `no_citations` | The claim carried no citation at all. |
| `malformed_citation` | The claim's only citations were not valid event ids. |
| `missing_id` | No cited id resolves to a real event in the store. |
| `no_assertions` | The claim asserted none of the four checkable facts. |
| `time_mismatch` | The asserted time is outside tolerance of the cited event. |
| `principal_mismatch` | The asserted principal does not match the cited event. |
| `action_mismatch` | The asserted action does not match the cited event. |
| `object_mismatch` | The asserted object does not match the cited event. |

## What reaches the report: checked fields only

The model's free `text` is a drafting aid, not the report's source of truth.
Nothing stops a model from stating a fact in prose that it never put in `asserts`
(for example, naming the domain administrator in `text` while asserting only
`action`), and the verifier cannot deterministically check arbitrary prose. So the
prose is never emitted as fact. An accepted claim carries the verified `asserts`
and its backing event, and the report renders the claim from those checked fields
only. The model's original prose is preserved alongside the claim as a
non-authoritative draft for the audit trail, but it is never rendered as a factual
statement. This is the fence made literal: the model proposes wording, but only
fields the verifier confirmed reach the reader as facts (AGENTS.md prime
directive). The practical consequence: every fact a model wants in the report must
be in `asserts`, where it is checked, or it does not appear.

## The generate-test-refine loop

The engine drives the loop in PRD Section 11 (FR23 to FR25):

1. Build the compact event view and ask the model to draft the narrative as
   claims (round 0).
2. Parse and verify every claim. Accepted claims are set aside. Each rejected
   claim is recorded in the audit log with its round, citations, reason, and a
   human-readable detail.
3. If any claim was rejected and rounds remain, resubmit just the rejected claims
   for revision. Each outstanding claim carries a stable `claim_id`, sent to the
   model in its revision request. The model returns a revised claim that names the
   id it fixes in a `revises` field, so the engine matches a revision to the claim
   it replaces by id, never by position (a revision that omits an earlier claim
   while fixing a later one is handled correctly). The revisions are re-verified; a
   revised claim that now passes is accepted, and its original rejection stays in
   the audit log for transparency. A returned claim with no `revises` (or an
   unknown id) is treated as a fresh claim and is still fully verified, so a
   revision round can never introduce an unverified claim.
4. An outstanding claim that no revision addresses (the model omitted it, or the
   revision output was unparseable) is carried to the final round and then dropped
   and recorded, never silently lost.
5. Repeat up to `max_rounds` revision rounds (default 2).
6. After the final round, drop any claim that is still unsupported. A dropped
   claim never reaches the report and is flagged `dropped` in the audit log
   (FR24, FR25).

The output is the verified narrative (the accepted claims, each linked to its
backing event for inline citation in the report, FR32) plus the rejected-claims
audit, which ships with every report so the rejections are transparent.

## Guarantees

- Citation accuracy is 1.0 by construction: an emitted claim has, by definition,
  a cited event whose fields are consistent with everything it asserts. Anything
  less is a verifier bug, not an acceptable output.
- The hallucination-rejection rate is measured, not asserted. The hallucination
  trap (FR35, `samples/hallucination_trap.json`) seeds deliberately fabricated
  claims (a nonexistent event, a wrong time, a wrong principal, a wrong action, a
  wrong object, a malformed citation) and the test asserts the verifier rejects
  every one. That fixture is the seed set behind the headline number.
- The model is fenced: it only ever sees the compact, id-addressed view, it must
  commit to machine-checkable assertions, and it never has the authority to state
  a fact the deterministic layer has not confirmed.
