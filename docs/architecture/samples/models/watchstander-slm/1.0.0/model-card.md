# watchstander-slm 1.0.0

Local small LLM that turns a constructed **incident** into watchstander **alert text**. It is not a detector. ONNX scores and rule fires already exist; this model writes `alert_title` and `alert_body` (plus structured tactics / techniques / recommend) for the operator list and NIS2 draft.

| Item | Value |
| --- | --- |
| Role | Alert generation (language), post-incident |
| Runtime | llama.cpp (or equivalent GGUF host) on the sensor |
| Size | ~8B, Q4_K_M (~5 GiB). Fits an 8 GiB industrial PC; GPU optional |
| Weights | `model.gguf` — **not** in git. Same signed-artifact path as ONNX |
| Decode | Constrained JSON (`operator-alert.schema.json`) |
| Timeout | 8 s; then `status=llm_unavailable` |
| Network | `prod` denies any remote endpoint |
| GT | Never in the prompt |

## Failure modes

- **Missing weights / load fail / timeout / invalid JSON:** `llm_unavailable`. Incident, risk, and NIS2 clocks still stand. UI uses the template fallback (`{severity} {rule_or_model} on {assets}; risk {total}`).
- **Technique hallucination:** post-validate `techniques ⊆ incident.techniques ∪ retrieved ATT&CK ids` in the prompt. Extra IDs dropped; if none remain, keep incident techniques and set `status=schema_invalid` only when title/body fail schema.
- **False attack wording on GNSS-degraded:** must follow `fault_likelihood` and rule `not` clauses. The model may not override `fault_vs_attack` against those inputs.

## Not this model

Does not set `severity`, `risk.total`, or `nis2_significant`. Does not see raw CAN, honeypot blobs, or labels. Does not call tools that write the bus.
