# The verification model

This is the contract for the fence between a language model and the report (PRD
Section 11, AGENTS.md prime directive and Hard rule 4). It defines:

1. what the model is shown,
2. the claim-and-citation format it must return,
3. the rules the deterministic verifier applies to every claim,
4. what a reader of the report actually sees, and
5. how the guarantee is measured.

The rule everything hangs on: no factual claim reaches a report unless it resolves
to a real, deterministically extracted timeline event by `event_id`, and the facts
it asserts (time, principal, action, object) are consistent with that event. The
deterministic layer is the source of truth. The model proposes; the verifier
disposes.

## 1. What the model sees

The model never sees evidence files, `details`, command lines, or file contents.
It sees a compact, id-addressed view of each event (FR17):

| Field | Why it is shown |
| --- | --- |
| `event_id` | The only way a claim can point at evidence. |
| `datetime`, `principal`, `action`, `object` | The four facts a claim may assert, so the verifier can check them. |
| `host`, `message` | Where the event happened, and the source's own one-line summary (for a detection source, the rule title). |
| `techniques` | The event's ATT&CK technique ids, decided deterministically by the tagger. |
| `severity` | The detection rule's severity, normalized to `informational`, `low`, `medium`, `high`, or `critical`. |

`techniques` and `severity` exist to help a model choose which events tell the
story. They are not assertable facts: a claim cannot assert a technique.

**The view budget.** A large case is cut to at most `--view-budget` events
(default 300) before it is shown. The cut is deterministic: events carrying an
ATT&CK technique first, then by severity, then chronologically; the chosen events
are shown in chronological order, and the prompt states how many were left out.
The cut changes only what the model sees. Every claim is still verified against
every event in the case.

**Cloud redaction.** On the local path the view above is sent as is; evidence stays
on the host. A cloud provider is opt-in (`--allow-cloud`) and receives a redacted
view (decision D5, FR36): the free-text `message` and the `principal` are replaced
with `[redacted]`, indicators (IP addresses, domains, hashes, paths) and usernames
inside `object` are blanked, and `host` can be stripped too
(`CASEBOUND_REDACT_HOST=1`). `event_id`, `datetime`, `action`, `techniques`, and
`severity` pass, because they address the event or describe its class rather than
its content. Redaction limits what a cloud claim can assert; it never weakens the
check, because the verifier compares every claim with the full, unredacted events
on the host.

## 2. The claim format

The model returns one JSON object. Its `claims` array holds one object per factual
statement:

```json
{
  "claims": [
    {
      "text": "Word spawned an encoded PowerShell as jdoe.",
      "citations": ["6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"],
      "asserts": {
        "datetime": "2026-03-14T08:42:17Z",
        "principal": "CORP\\jdoe",
        "action": "process_create",
        "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      },
      "revises": null
    }
  ]
}
```

- `text`: a readable sentence for the audit trail. It is never checked and never
  shown as a fact (see section 4).
- `citations`: one or more `event_id` strings, each a 64-character lowercase
  SHA-256 hex digest (`docs/schema.md`).
- `asserts`: the facts the claim commits to. Four optional fields are recognized,
  `datetime`, `principal`, `action`, and `object`, mirroring the canonical event
  fields. A null or empty value means the claim does not assert that field. At
  least one must be asserted.
- `revises`: on a revision round, the `claim_id` of the rejected claim this one
  replaces; otherwise null or absent.

The format is published as a JSON Schema,
[`casebound/data/claims.schema.json`](../casebound/data/claims.schema.json), in the
strict form (every property required, optional ones nullable) that structured
output APIs accept. The bundled providers send it to the model where the API
supports it; the parser accepts any conforming document regardless of how it was
produced.

### Parsing rules

Parsing is deterministic (FR19):

- The document must be valid JSON: the object form above or a bare array of
  claims. A Markdown code fence around it is tolerated. Anything else is
  unparseable and yields no claims for that round.
- A claim without `text` is skipped.
- Each citation is classified as well formed (it matches the `event_id` pattern,
  after trimming and lower-casing) or malformed (anything else, for example
  `EVENT-80038` or a truncated id). Malformed citations are kept for the audit log
  and provide no support.

## 3. The rules

A claim is accepted if and only if all of these hold, checked in this order:

1. It carries at least one citation and no malformed citation.
2. It asserts at least one of the four facts.
3. Every cited `event_id` resolves to a real event in the case (FR20). A single
   unresolved citation rejects the claim, so every citation on an accepted claim
   links to real evidence (FR32).
4. At least one cited event is consistent with every asserted fact (FR21). One
   event must back the whole claim, which prevents stitching one event's
   principal onto another event's action. Other cited events are kept as context.

When no cited event backs every fact, the rejection reason is the first failing
field of the first cited event, with fields checked in the order `datetime`,
`principal`, `action`, `object`.

### Per-field comparison

Only asserted fields are checked. A field the event does not record (a null
`principal` or `object`) can never satisfy an assertion about it: a claim cannot
assert a fact the evidence does not contain.

- `datetime` (`time_mismatch`): both values are parsed as instants and must agree
  within the tolerance, 1 second by default (`FieldTolerance`). Any ISO 8601 offset
  is accepted, so `2026-03-14T09:42:17+01:00` matches `2026-03-14T08:42:17Z`. An
  unparseable value is a mismatch.
- `principal` (`principal_mismatch`), `action` (`action_mismatch`), and `object`
  (`object_mismatch`): compared as text after trimming and case-folding, because
  Windows accounts and paths are case-insensitive. A Unicode look-alike (a Cyrillic
  `а` for a Latin `a`) is a different string and does not match.

### Rejection reasons

| Reason | Meaning |
| --- | --- |
| `malformed_citation` | A citation is not a valid event id (one malformed citation rejects the claim). |
| `no_citations` | The claim cites nothing. |
| `no_assertions` | The claim asserts none of the four facts. |
| `missing_id` | A cited id does not resolve to an event in the case. |
| `time_mismatch` | No cited event is within tolerance of the asserted time. |
| `principal_mismatch` | No cited event has the asserted principal. |
| `action_mismatch` | No cited event has the asserted action. |
| `object_mismatch` | No cited event has the asserted object. |

A rejection detail quotes only the value the model asserted, never the event's
value. Details travel back to the model as revision hints, and on the cloud path a
hint must not carry evidence the redaction pass removed.

## 4. What reaches the reader

Nothing the model writes is shown as a fact. For each accepted claim, the report
shows a sentence composed by `casebound.report.phrasing` from the backing event's
own canonical fields, for example:

> CORP\jdoe started C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.

beside the event's time, host, detection title, severity, and ATT&CK techniques,
a `verified:` badge naming the facts the model asserted and the verifier confirmed,
and a link to the backing event in the evidence appendix. Other cited events are
listed as context. The model's `text` and its spellings of the asserted values
(a different case, a non-UTC offset) never appear; the tolerant comparison lets
them match, but the reader sees the evidence's own values. A rejected claim appears
only in the rejected-claims audit, labeled as a rejected model draft, with its
reason.

The model therefore decides which events the narrative covers and in what order.
It cannot decide what the narrative says about them.

## 5. The loop

The engine runs PRD Section 11's generate, test, and refine loop (FR23 to FR25):

1. Round 0: the model drafts claims from the view.
2. Every claim is parsed and verified. Accepted claims are kept. Each rejected
   claim gets a stable `claim_id` and an audit entry with its round, citations,
   reason, and detail.
3. While rounds remain (`--max-rounds`, default 2), the rejected claims go back to
   the model with their `claim_id`, text, citations, reason, and detail. A revision
   names the claim it fixes in `revises`, so revisions are matched by id, never by
   position. A returned claim with no `revises`, or an unknown one, is verified as
   a fresh claim; a revision round can never introduce an unverified claim.
4. A rejected claim that no revision addresses (omitted, or the output was
   unparseable) is carried to the final round.
5. After the final round, every still-unsupported claim is dropped and flagged
   `dropped` in the audit. A dropped claim never reaches the narrative.

## Checking claims from anywhere

The verifier does not care who drafted a claim. `casebound verify` checks a claims
file written by another tool, another model, or a person against a case's
`events.jsonl`:

```console
$ casebound verify claims.json --events out/events.jsonl --out verdicts.json
ACCEPT  CORP\jdoe started C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe. [6fb28f7a4aa4]
REJECT  The domain administrator launched PowerShell.
        principal_mismatch: asserted principal 'CORP\Administrator' does not match the principal of event 6fb28f7a4aa4
1 of 2 claim(s) verified against 37 event(s)
wrote verdicts.json
```

It exits 0 when every claim is accepted and 1 when any is rejected.

## How the guarantee is measured

- **The verifier benchmark** (`casebound.evaluation`, printed by `casebound demo`
  and written to `metrics.json`). From every event of a case it derives claims in
  the model's format and runs them through the real parser and checks. Fourteen
  fabrication classes must all be rejected: a nonexistent id, a truncated id, a
  record number as a citation, no citation, no assertion, a time just outside the
  tolerance, a time hours off, a swapped principal, action, or object, a Unicode
  look-alike object, a claim stitched from two events, and a true claim carrying
  one dangling or one malformed extra citation. Eight grounded classes must all be
  accepted: exact, re-cased, whitespace-padded, a non-UTC offset for the same
  instant, a sub-second difference within tolerance, a subset of the fields, an
  upper-case id, and an extra context citation. On the bundled scenario that is
  495 fabricated claims rejected and 296 grounded claims accepted, with zero
  false accepts and zero false rejects. The test suite also proves the benchmark
  has teeth: a verifier weakened in any single check produces false accepts in
  exactly the classes that probe it.
- **Citation accuracy.** Every claim a narrative run accepted is re-verified from
  scratch. The target is 1.0; less is a verifier bug.
- **The hallucination trap** (FR35, `samples/hallucination_trap.json`): one
  grounded claim and eight fabricated claims, one per rejection reason, pinned
  against the bundled scenario. The suite asserts every fabrication is rejected for
  its expected reason.
- **Property-based tests** (`tests/test_verify.py`): for every event of the
  scenario, its exact facts are accepted, and any single fact changed beyond
  tolerance is rejected with the matching reason.
