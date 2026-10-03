# SYN-001 — Synthetic process-context example

**SYNTHETIC: all findings and timestamps below are invented; no image was analyzed.**
Report specification: 0.1. Status: complete with limitations (demonstration only).

## Executive summary

The fabricated fixture describes a `System` process created at 12:00 UTC followed
by `sample-agent.exe` (PID 424) at 12:01 UTC on 1 January 2020. The mock process
record gives PID 4 as the latter's parent. This illustrates recorded creation
order and reported parent identity, not a demonstrated attack or a verified
causal chain (SYN-F001).

The simulated network scan failed because the mock symbol provider was unavailable.
Network activity therefore remains unknown (SYN-F002). This example provides no
basis for concluding that the system was compromised or clean, attributing an
actor, establishing initial access, or claiming traffic. All interpretation is
limited to deliberately fabricated text, not actual forensic observations.

## Scope and evidence

| Item | Value |
| --- | --- |
| Source ID | SYN-E001, harmless generated text, not a memory image |
| Source identity | See manifest for SHA-256 and byte size of the actual fixture |
| Acquisition time/method | Not applicable; no acquisition occurred |
| Guest OS/architecture | Invented Windows/x86 labels in SYN-A001; unverified |
| Analysis period | Simulated 2020-01-02T12:00:00Z to 2020-01-02T12:03:00Z |
| Tools | Simulated only; no Python/MCP/Volatility analysis versions are asserted |
| Integrity | Fixture before/after hashes match; this is not real chain-of-custody evidence |

Identity and hashes: [case-manifest.json](case-manifest.json).
Input fixture: [SYN-E001](artifacts/SYN-E001-input.txt).
Mock OS context: [SYN-A001](artifacts/SYN-C001-info.json), `records[0:2]`.

## Reconstructed event timeline

| Original time | Artifact meaning | Evidence | Confidence |
| --- | --- | --- | --- |
| 2020-01-01T12:00:00Z | Invented process creation, PID 4 | SYN-A002, records[0].CreateTime | Exact within fixture only |
| 2020-01-01T12:01:00Z | Invented process creation, PID 424 | SYN-A002, records[1].CreateTime | Exact within fixture only |

UTC is explicit in the fixture; no actual host clock or acquisition time is known.
The later simulated investigation occurred on 2 January; it is not part of the
captured-system chronology.

## Technical findings

### SYN-F001 — Mock process ancestry is context, not malware evidence

**Observed in the fabricated output:** [SYN-A002](artifacts/SYN-C002-pslist.json),
`records[1]`, contains PID `424`, PPID `4`, name `sample-agent.exe`, and virtual
object offset `0x2000`. [SYN-A003](artifacts/SYN-C002-pslist.txt), line 4, is its
readable rendering. These values describe the mock record only.

**Recorded dependency:** SYN-C001 supplies invented OS context → ask which
processes are represented → SYN-C002 simulates `run_plugin` with
`{"image":"synthetic.mem","plugin":"windows.pslist.PsList","arguments":[]}`
→ PID 424 and parent field 4 → treat as process context → SYN-C003 attempts a
simulated network-coverage pivot. These calls were not executed.

**Inference/alternatives:** The earlier creation time and parent field are consistent
within the fixture. No executable identity, legitimacy, PID reuse, injection,
persistence, or malicious behavior was tested. A process name is not sufficient
to determine intent. Confidence is high only in correctly transcribing the
synthetic records; the example supports no claim about a real system.

### SYN-F002 — Mock network failure leaves activity unresolved

[SYN-A004](artifacts/SYN-C003-stderr.txt), line 2, says:

> Mock symbol provider unavailable; network scan was not completed.

SYN-C003 branches from the mock process context to ask whether network artifacts
can be enumerated. The simulated `windows.netscan.NetScan` call fails. Its failure
cannot establish absence of network activity. The hypothesis remains untested;
a real case would need matching symbols and a supported plugin before interpreting
network results. This fabricated message is not represented as a real framework
error or a statement about a particular Windows release.

## Investigative workflow and coverage

All entries in [investigation.jsonl](investigation.jsonl) are marked synthetic.

| Call; prerequisite | Question and simulated call | Evidence; result | Next-step rationale; disposition |
| --- | --- | --- | --- |
| SYN-C001; none | OS context? `get_image_info(image="synthetic.mem")` | SYN-A001; simulated success | Use mock Windows context for process question; context established only in fixture |
| SYN-C002; SYN-C001 | What processes? `run_plugin(..., plugin="windows.pslist.PsList", arguments=[])` | SYN-A002/SYN-A003; 2 mock rows | Ask about network coverage; malicious-process hypothesis unsupported |
| SYN-C003; SYN-C002 | Network objects? `run_plugin(..., plugin="windows.netscan.NetScan", arguments=[])` | SYN-A004; simulated error | Matching symbols would be needed; network hypothesis untested |

## Limitations and unresolved questions

This is not an investigation of a real image. All process/OS results are fabricated;
no acquisition, executable validation, symbols, injection checks, persistence,
files, registry, or actual network analysis occurred. The failed mock call is
preserved as a coverage gap. No real case conclusions or malware identification
are possible. Actual Volatility support cannot be assessed from this fixture.

## Hunting content

No hunting package is justified. The example establishes no malicious behavior and
provides no validated detection logic or telemetry coverage. No rules were tested.

## Reproduction and references

The outputs were written as synthetic text; no Volatility argv was executed.
`argv` is null in each simulated record. Names/options demonstrate the logging
contract, not a validated command for an unknown image. Actual analysis must
first discover the installed tools/plugins and use real acquisition evidence.

The [manifest](case-manifest.json) maps stable IDs to paths, sizes, and SHA-256.
[SHA256SUMS](SHA256SUMS) covers the complete example bundle except itself. No
external malware literature is used. This example was authored with AI assistance;
its purpose is format demonstration, with no claim of human forensic certification.

## IOC appendix

There are no justified malicious indicators. The following row is explicitly
benign/unknown context for the export contract, not a detection recommendation.

| Type; value | Evidence | Confidence; relevance | Status; context |
| --- | --- | --- | --- |
| process_name; `sample-agent.exe` | SYN-A002 records[1].ImageFileName | High transcription confidence only; contextual | Synthetic observed field; no malicious significance established |

Exact values: [iocs.csv](iocs.csv).
