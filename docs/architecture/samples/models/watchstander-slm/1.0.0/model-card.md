# watchstander-slm 1.0.0

Local small LLM that turns a constructed **incident** into watchstander **alert text**. It is not a detector. ONNX scores and rule fires already exist; this model writes `alert_title` and `alert_body` (plus structured tactics / techniques / recommend) for the operator list and NIS2 draft.

| Item | Value |
| --- | --- |
| Role | Alert generation (language), post-incident |
| Runtime | Local Ollama on loopback (`qwen2:1.5b` default); optional GGUF |
| Size | Smallest local instruct tag (lab host: 1.5B Q4) |
| Weights | Ollama tag via `OTLAB_SLM_MODEL` / `OTLAB_CYBERPAL_MODEL`; `model.gguf` optional |
| Timeout | Health check is `/api/tags` (2 s). Ingest does not wait on a generate |
| Network | `prod` denies any remote `LLM_ENDPOINT` |
| GT | Never in the prompt |

## Pointing the app at a model

```bash
ollama serve
ollama pull qwen2:1.5b
export OTLAB_SLM_MODEL=qwen2:1.5b
uv run python -m ot_sensor.cyberpal
```

The dashboard **Local SLM** pill is `ok` and shows the tag when that model is listed. Ollama down → `llm_unavailable` and the template title `{severity} {rule} on {assets}; risk {total}`.

## Failure modes

- **Ollama down / missing tag / load fail:** `llm_unavailable`. Incident, risk, and NIS2 clocks still stand.
- **Technique hallucination:** post-validate `techniques ⊆ incident.techniques ∪ retrieved ATT&CK ids` in the prompt. Extra IDs dropped; if none remain, keep incident techniques and set `status=schema_invalid` only when title/body fail schema.
- **False attack wording on GNSS-degraded:** must follow `fault_likelihood` and rule `not` clauses. The model may not override `fault_vs_attack` against those inputs.

## Not this model

Does not set `severity`, `risk.total`, or `nis2_significant`. Does not see raw CAN, honeypot blobs, or labels. Does not call tools that write the bus. Does not replace CyberPal investigation chat.
