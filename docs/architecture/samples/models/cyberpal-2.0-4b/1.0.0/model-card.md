# cyberpal-2.0-4b 1.0.0

Local cybersecurity assistant for **incident interpretation** and **investigation Q&A**. It is not a detector. Correlation already joined ONNX scores and rule fires; this model explains that case to a watchstander and answers follow-up questions.

One **chat session per incident**. The prompt is the correlated incident JSON (alerts, rules, models, assets, graph, evidence_summary, risk, NIS2). It does not see raw CAN, honeypot blobs, or ground-truth labels.

| Item | Value |
| --- | --- |
| Role | Investigation assistant, post-correlation |
| Runtime | Local Ollama on loopback, GGUF |
| Size | ~4B, Q4_K_M (~2.5 GiB) |
| Weights | `model.gguf` — **not** in git |
| Timeout | 90 s; then heuristic fallback |
| Network | `prod` denies any non-loopback endpoint |
| GT | Never in the prompt |

Official **CyberPal 2.0-4B** weights are not on Hugging Face yet (the public drop is `cyber-pal-security/CyberPal2.0-20B`). The lab GGUF is Qwen3-4B Instruct in the same size class the paper fine-tuned from Qwen3-4B-base.

## Failure modes

Missing weights / Ollama down / timeout: `llm_unavailable`. The UI still shows a structured briefing built from the incident JSON. Chat answers stay grounded in that JSON.

## Not this model

Does not fire detections, set risk, or write the bus. Does not replace watchstander-slm alert title/body.
