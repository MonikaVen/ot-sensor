"""Local CyberPal runtime: Ollama SLM for incident investigation.

Official CyberPal 2.0-4B is not published. This lab uses the smallest local
Ollama instruct model that is already present (qwen2:1.5b on this host) with
the CyberPal system prompt. Override with OTLAB_CYBERPAL_MODEL.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ot_sensor.paths import lab_root

OLLAMA_ALIAS = "cyberpal"
HF_OFFICIAL = "cyber-pal-security/CyberPal2.0-4B"
HF_FALLBACK_REPO = "unsloth/Qwen3-4B-Instruct-2507-GGUF"
HF_FALLBACK_FILE = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
SYSTEM = (
    "You are CyberPal, a cybersecurity-expert assistant on a listen-only NMEA 2000 OT sensor. "
    "You interpret correlated incidents for a watchstander. You do not detect — ONNX and rules already fired. "
    "Use only the supplied incident JSON. Do not invent CAN payloads, labels, attack_id, or ground truth. "
    "Do not recommend transmitting on the bus, changing engines/autopilot, malware scans, or auto-closing incidents. "
    "Recommend observe, distrust talkers, TAP health, and gateway review only. "
    "Cite rule_id, asset_id, techniques, and feature names from the JSON. "
    "Short unique sentences. No repetition."
)

# Smallest-first. qwen2:1.5b is the SLM already on this lab host.
_CANDIDATES = (
    "cyberpal",
    "qwen2:1.5b",
    "cyberpal-2.0-4b",
    "qwen2:latest",
    "qwen2",
)

_resolved: str | None = None
_alias_tried = False
_stopped_large = False
_chat_lock = threading.Lock()


def ollama_url() -> str:
    return (os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")


def configured_model() -> str:
    return (os.environ.get("OTLAB_CYBERPAL_MODEL") or os.environ.get("OTLAB_SLM_MODEL") or "").strip()


def model_dir(work: Path | None = None, repo: Path | None = None) -> Path:
    if os.environ.get("OTLAB_CYBERPAL"):
        return Path(os.environ["OTLAB_CYBERPAL"])
    if work is not None:
        return Path(work) / "models" / "cyberpal-2.0-4b"
    return (repo or lab_root()) / "otlab-work" / "models" / "cyberpal-2.0-4b"


def gguf_path(work: Path | None = None, repo: Path | None = None) -> Path | None:
    d = model_dir(work, repo)
    named = d / "model.gguf"
    if named.exists():
        return named.resolve()
    if d.is_dir():
        found = sorted(d.glob("*.gguf"))
        if found:
            return found[0].resolve()
    pack = (repo or lab_root()) / "docs/architecture/samples/models/cyberpal-2.0-4b/1.0.0/model.gguf"
    return pack.resolve() if pack.exists() else None


def ollama_tags() -> list[str]:
    try:
        with urlopen(ollama_url() + "/api/tags", timeout=2) as resp:
            data = json.load(resp)
    except (URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    names: list[str] = []
    for m in data.get("models") or []:
        name = str(m.get("name") or "")
        if not name:
            continue
        names.append(name)
        names.append(name.split(":")[0])
    return names


def _names(tags: list[str]) -> set[str]:
    names: set[str] = set()
    for t in tags:
        names.add(t)
        names.add(t.split(":")[0])
        if t.endswith(":latest"):
            names.add(t[: -len(":latest")])
    return names


def _pick(tags: list[str]) -> str | None:
    names = _names(tags)
    env = configured_model()
    if env and (env in names or env.split(":")[0] in names):
        return env
    for name in _CANDIDATES:
        if name in names:
            return name
    return None


def resolve_model() -> str | None:
    global _resolved
    if _resolved:
        return _resolved
    picked = _pick(ollama_tags())
    if picked:
        _resolved = picked
    return _resolved


def base_model(runtime: str | None = None) -> str | None:
    env = configured_model()
    if env:
        return env
    name = runtime or _resolved or resolve_model()
    if name in (None, OLLAMA_ALIAS, "cyberpal:latest"):
        return "qwen2:1.5b"
    return name


def _stop_competing_models(keep: str) -> None:
    """Unload the 4B GGUF so the small SLM can run on this CPU host."""
    global _stopped_large
    if _stopped_large:
        return
    _stopped_large = True
    for name in ("cyberpal-2.0-4b", "qwen2:latest"):
        if name in (keep, keep.split(":")[0]):
            continue
        try:
            subprocess.run(["ollama", "stop", name], check=False, timeout=10, capture_output=True)
        except (OSError, subprocess.SubprocessError):
            pass


def ensure_alias() -> str | None:
    """Point alias `cyberpal` at the smallest local instruct SLM (qwen2:1.5b)."""
    global _alias_tried, _resolved
    tags = ollama_tags()
    names = _names(tags)
    env = configured_model()
    if env:
        _resolved = _pick(tags)
        return _resolved
    if "cyberpal" in names:
        _resolved = "cyberpal"
        _stop_competing_models(_resolved)
        return _resolved
    if _alias_tried:
        _resolved = _pick(tags)
        return _resolved
    _alias_tried = True
    base = None
    for name in ("qwen2:1.5b", "qwen2:latest", "qwen2"):
        if name in names:
            base = "qwen2:1.5b" if name.startswith("qwen2:1.5b") else name
            break
    if not base:
        _resolved = _pick(tags)
        return _resolved
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Modelfile"
        path.write_text(
            f"FROM {base}\nSYSTEM \"\"\"{SYSTEM}\"\"\"\nPARAMETER temperature 0.2\nPARAMETER num_ctx 2048\nPARAMETER num_predict 180\n",
            encoding="utf-8",
        )
        try:
            subprocess.run(["ollama", "create", OLLAMA_ALIAS, "-f", str(path)], check=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            _resolved = base
            return _resolved
    _resolved = OLLAMA_ALIAS
    _stop_competing_models(_resolved)
    return _resolved


def ollama_ready() -> bool:
    return bool(ensure_alias())


def download_gguf(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / HF_FALLBACK_FILE
    if not target.exists():
        cmd = shutil.which("huggingface-cli")
        if not cmd:
            raise RuntimeError("huggingface-cli not found")
        subprocess.run(
            [cmd, "download", HF_FALLBACK_REPO, HF_FALLBACK_FILE, "--local-dir", str(dest)],
            check=True,
        )
    link = dest / "model.gguf"
    if not link.exists():
        try:
            link.symlink_to(target.name)
        except OSError:
            shutil.copy2(target, link)
    (dest / "SOURCE.txt").write_text(
        f"official={HF_OFFICIAL} (not published)\n"
        f"small_slm=qwen2:1.5b (default lab runtime)\n"
        f"fallback_gguf={HF_FALLBACK_REPO}/{HF_FALLBACK_FILE}\n",
        encoding="utf-8",
    )
    return link if link.exists() else target


def import_ollama(gguf: Path) -> None:
    gguf = Path(gguf).resolve()
    modelfile = gguf.parent / "Modelfile"
    modelfile.write_text(
        f"FROM {gguf}\nSYSTEM \"\"\"{SYSTEM}\"\"\"\nPARAMETER temperature 0.2\nPARAMETER num_ctx 2048\nPARAMETER num_predict 180\n",
        encoding="utf-8",
    )
    subprocess.run(["ollama", "create", "cyberpal-2.0-4b", "-f", str(modelfile)], check=True, cwd=str(gguf.parent))


def chat(messages: list[dict], timeout: int = 70) -> str:
    runtime = ensure_alias() or resolve_model()
    if not runtime:
        raise RuntimeError("no local Ollama SLM for CyberPal")
    model = base_model(runtime) or runtime
    payload = list(messages)
    if not payload or payload[0].get("role") != "system":
        payload = [{"role": "system", "content": SYSTEM}, *payload]
    body = json.dumps(
        {
            "model": model,
            "messages": payload,
            "stream": False,
            "think": False,
            "keep_alive": "30m",
            "options": {"temperature": 0.2, "num_ctx": 2048, "num_predict": 80, "repeat_penalty": 1.4},
        }
    ).encode()
    req = Request(ollama_url() + "/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with _chat_lock:
        try:
            with urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
        except HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"ollama {e.code}: {detail}") from e
    content = ((data.get("message") or {}).get("content") or "").strip()
    if "</think>" in content:
        content = content.split("</think>", 1)[-1].strip()
    if not content:
        raise RuntimeError("empty CyberPal response")
    return _collapse(content)


def _collapse(text: str) -> str:
    seen: set[str] = set()
    kept: list[str] = []
    for chunk in text.replace("\n", ". ").split("."):
        s = " ".join(chunk.split())
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        kept.append(s)
    return ". ".join(kept) + ("." if kept else "")


if __name__ == "__main__":
    model = ensure_alias()
    print("runtime", model or "unavailable")
    print("tags", sorted(set(ollama_tags())))
    if model:
        print(chat([{"role": "user", "content": "Reply with the single word ready."}]))
