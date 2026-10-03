# {{CASE_ID}} — {{CASE_TITLE}}

Report specification: 0.1. Status: {{COMPLETION_STATUS}}.
Analysis: {{START_UTC}} to {{END_UTC}}. Revision: {{REVISION_OR_FIRST}}.

> Editable template fields use `{{...}}`. Replace them with observed values or
> explicit unknowns; remove these editing notes from a completed report. Follow
> [REPORT_SPEC.md](../../docs/REPORT_SPEC.md), the authoritative contract.

## Executive summary

{{WRITE_AFTER_ANALYSIS: What was found, in the chronology the evidence supports.
Separate observed activity, inferred order, and unknown stages. State supported
impact, key limitation, and confidence. Reference finding IDs. Do not manufacture
initial access or an intrusion story.}}

## Scope and evidence

| Item | Value and uncertainty |
| --- | --- |
| Source evidence ID | {{EVIDENCE_ID}} |
| SHA-256; size | {{SHA256}}; {{SIZE_BYTES}} bytes |
| Provenance; source/archive identity | {{SOURCE_OR_UNKNOWN}} |
| Acquisition method/time | {{KNOWN_VALUE_WITH_TIMEZONE_OR_UNKNOWN}} |
| Guest OS/build/architecture; symbols | {{ACTUAL_DISCOVERY_REFERENCE}} |
| Analysis host and tool versions | {{ACTUAL_VERSIONS_NOT_ASSUMPTIONS}} |
| Before/after integrity | {{HASH_VERIFICATION_AND_REFERENCE}} |
| Scope/handling | {{TRAINING_OR_OPERATIONAL_STATUS_AND_LIMITS}} |

## Reconstructed event timeline

| Original time; timezone/uncertainty | Artifact meaning/event | Evidence/finding | Confidence |
| --- | --- | --- | --- |
| {{TIME_OR_UNKNOWN}} | {{EVENT_WITH_LIMITS}} | {{ARTIFACT_LOCATOR}} | {{QUALITATIVE_CONFIDENCE}} |

{{EXPLAIN_WHAT_CANNOT_BE_ORDERED_AND_KEEP_ANALYST_CALL_TIMES_SEPARATE}}

## Technical findings

### {{CASE_ID}}-F001 — {{EVIDENCE_SUPPORTED_CONCLUSION}}

**Significance and confidence:** {{WHY_THIS_MATTERS_AND_QUALITATIVE_CONFIDENCE}}

**Observed facts:** {{COMPACT_EXCERPT_AND_SAVED_ARTIFACT_LINK_WITH_ROW_FIELD_OFFSET}}

**Dependency chain:** {{PRIOR_OBSERVATION}} → {{QUESTION}} → {{CALL_ID_AND_EXACT_ARGS}}
→ {{OUTPUT_LOCATOR}} → {{SUPPORTED_INTERPRETATION}} → {{NEXT_STEP_OR_STOP_REASON}}.

**Corroboration and alternatives:** {{OTHER_ARTIFACTS_OR_BENIGN_EXPLANATIONS}}

**Inference and unknowns:** {{INFERENCE_SEPARATED_FROM_OBSERVATION_AND_LIMITS}}

## Investigative workflow and coverage

| Call; prerequisites | Question and tool/arguments | Evidence; status/result | Next-step rationale; hypothesis disposition |
| --- | --- | --- | --- |
| {{CALL_ID}}; {{PREREQUISITES_OR_NONE}} | {{QUESTION_AND_ACTUAL_CALL}} | {{ARTIFACT_AND_RESULT}} | {{RATIONALE_AND_DISPOSITION}} |

{{INCLUDE_MEANINGFUL_FAILURES_NEGATIVE_CONTRARY_AND_INCONCLUSIVE_EVIDENCE}}

## Limitations and unresolved questions

{{ACQUISITION_GAPS_SYMBOL_PROBLEMS_FAILED_UNSUPPORTED_PARTIAL_SCANS_UNSUPPORTED_CONCLUSIONS}}

{{ADDITIONAL_EVIDENCE_NEEDED_AND_HISTORICAL_VERSUS_CURRENT_FAILURES}}

## Hunting content

{{LINK_JUSTIFIED_PACKAGE_AND_ACTUAL_VALIDATION_STATUS_OR_EXPLAIN_OMISSION}}

## Reproduction and references

{{ACTUAL_RUN_IDS_COMMANDS_VERSIONS_HASHES_SYMBOL_ASSUMPTIONS_AND_RELATIVE_ARTIFACT_LINKS}}

{{SEPARATE_EXTERNAL_SOURCES_FROM_IMAGE_FINDINGS; STATE_AI_ASSISTANCE_AND_REVIEW_NEEDS}}

## IOC appendix

| Type; exact value | Evidence locator | Confidence; relevance | Observed/configured/carved; context |
| --- | --- | --- | --- |
| {{TYPE_AND_VALUE_OR_NO_JUSTIFIED_INDICATORS}} | {{ARTIFACT_ID_AND_LOCATOR}} | {{CONFIDENCE_AND_RELEVANCE}} | {{STATUS_AND_LIMITS}} |

Exact machine-readable values: [iocs.csv](iocs.csv). {{DISTINGUISH_CONTEXTUAL_VALUES_FROM_SUSPICIOUS_INDICATORS}}
