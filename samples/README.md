# Bundled samples

The synthetic evidence the demo, the evaluation, and much of the test suite run on.
Everything here is synthetic and safe (AGENTS.md Hard rule 3): lab hostnames, a
fictional `CORP` domain, fake SIDs, external addresses from the RFC 5737
documentation ranges, domains under the reserved `.example` TLD, and no working
payload.

## Files

| File | Made by | What it is |
| --- | --- | --- |
| `synthetic_hayabusa.csv` | `casebound generate` | A Hayabusa `csv-timeline` in the verbose profile: 37 detections across a workstation and a file server. |
| `ground_truth.json` | `casebound generate` | The labels: the 12 attack events, each with its record id, canonical fields, stage, the rule's own ATT&CK tags, and the current technique ids they resolve to. |
| `attack_navigator_layer.json` | `casebound demo` | The ATT&CK Navigator layer the demo writes, committed so the artifact can be inspected without running anything. |
| `hallucination_trap.json` | by hand | The FR35 trap: one grounded claim and eight fabricated claims, one per rejection reason, citing real events of this scenario. |

The test suite checks that the first three are exactly what the code regenerates,
and that every trap claim gets its expected verdict.

## The scenario

`office_intrusion`, on the morning of 2026-03-14, rendered in the analyst's local
time (US Eastern, UTC-4):

1. Initial access: a phishing macro in Word spawns an encoded PowerShell
   (T1566.001, T1059.001).
2. Command and control: PowerShell pulls a stager over HTTPS (T1071.001, T1105).
3. Persistence: a Run key (T1547.001) and a scheduled task (T1053.005) point at the
   implant.
4. Credential access: the implant reads LSASS memory (T1003.001).
5. Lateral movement: a network logon with a stolen service account (T1078.002), an
   `ADMIN$` share mount (T1021.002), and a remote service that is installed
   (T1543.003) and runs (T1569.002).
6. Collection and exfiltration: data is archived (T1560.001) and sent to an outside
   host (T1041).
7. Defense impairment: the Security log is cleared. The rule tags it with the
   revoked `T1070.001`; the label is its ATT&CK 19 successor, `T1685.005`, so the
   tagger's translation is exercised end to end.

Around it are 25 benign detections a real triage would also contain: service
logons, privilege assignments, a mistyped password, service state changes, and
look-alikes of the attack (a OneDrive autostart Run key, a Defender scan that opens
LSASS, a Windows maintenance task, an Edge updater service install, an
administrator's scheduled PowerShell). The look-alikes come from informational
rules without ATT&CK tags, so they stay off the report's matrix; they are what the
mapping table alone misreads, which is why its published precision is lower.

The timeline is rendered the way Hayabusa's verbose profile prints it: abbreviated
channels (`Sec`, `Sys`, `Sysmon`) and Details keys (`TgtUser`, `SrcIP`, `Proc`),
the remaining fields in `ExtraFieldInfo`, `n/a` for a template field a record
lacks, the rule file and id, and the EVTX file each record came from.

## Regenerating

The committed files are reproduced byte for byte by:

```bash
casebound generate            # samples/synthetic_hayabusa.csv and ground_truth.json
casebound demo -o out         # out/attack_navigator_layer.json, then copy it here
```

A different seed changes the cosmetic identifiers (record ids, hashes) but not the
labeled events or the technique set:

```bash
casebound generate --seed 42 --out-dir /tmp/scenario
```

The trap cites events by `event_id`, which the seed does not affect: record ids
and hashes are outside an event's identity, so the trap holds for any seed.
