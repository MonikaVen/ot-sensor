# CyberPal 1.0.0 (lab SLM)

Local cybersecurity assistant for **incident interpretation** and **investigation Q&A**. It is not a detector. Correlation already joined ONNX scores and rule fires; this model explains that case to a watchstander and answers follow-up questions.

One **chat session per incident**. The prompt is the correlated incident JSON (alerts, rules, models, assets, graph, evidence_summary, risk, NIS2). It does not see raw CAN, honeypot blobs, or ground-truth labels.

| Item | Value |
| --- | --- |
| Role | Investigation assistant, post-correlation |
| Runtime | Local Ollama on loopback |
| Default SLM | `qwen2:1.5b` (already on the lab host); alias `cyberpal` |
| Override | `OTLAB_CYBERPAL_MODEL` |
| Timeout | 70 s; then heuristic fallback |
| Network | `prod` denies any non-loopback endpoint |
| GT | Never in the prompt |

Official **CyberPal 2.0-4B** weights are not on Hugging Face yet. This lab uses the smallest available local instruct SLM with the CyberPal system prompt so investigation stays interactive on CPU.

## Failure modes

Ollama down / timeout: `llm_unavailable`. The UI still shows a structured briefing built from the incident JSON. Chat answers stay grounded in that JSON.

## Not this model

Does not fire detections, set risk, or write the bus. Does not replace watchstander-slm alert title/body.
