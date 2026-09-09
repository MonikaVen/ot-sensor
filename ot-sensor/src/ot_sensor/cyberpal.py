"""Locate / import the local 4B CyberPal runtime (Ollama + GGUF)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ot_sensor.paths import lab_root

OLLAMA_MODEL = "cyberpal-2.0-4b"
HF_OFFICIAL = "cyber-pal-security/CyberPal2.0-4B"
HF_FALLBACK_REPO = "unsloth/Qwen3-4B-Instruct-2507-GGUF"
HF_FALLBACK_FILE = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
SYSTEM = (
    "You are CyberPal, a cybersecurity-expert assistant on a listen-only NMEA 2000 OT sensor. "
    "You interpret correlated incidents for a watchstander. You do not detect — ONNX and rules already fired. "
    "Use only the supplied incident JSON. Do not invent CAN payloads, labels, attack_id, or ground truth. "
    "Do not recommend transmitting on the bus, changing engines/autopilot, or auto-closing incidents. "
    "Recommend observe, distrust talkers, TAP health, and gateway review only. "
    "Cite rule_id, asset_id, techniques, and feature names from the JSON. Be concise."
)


def ollama_url() -> str:
    return (os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")


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
    names = []
    for m in data.get("models") or []:
        name = str(m.get("name") or "")
        if name:
            names.append(name.split(":")[0])
            names.append(name)
    return names


def ollama_ready() -> bool:
    return OLLAMA_MODEL in ollama_tags() or f"{OLLAMA_MODEL}:latest" in ollama_tags()


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
        f"official={HF_OFFICIAL} (not published)\nfallback={HF_FALLBACK_REPO}/{HF_FALLBACK_FILE}\n",
        encoding="utf-8",
    )
    return link if link.exists() else target


def import_ollama(gguf: Path) -> None:
    gguf = Path(gguf).resolve()
    modelfile = gguf.parent / "Modelfile"
    modelfile.write_text(
        f"FROM {gguf}\nSYSTEM \"\"\"{SYSTEM}\"\"\"\nPARAMETER temperature 0.2\nPARAMETER num_ctx 4096\nPARAMETER num_predict 320\n",
        encoding="utf-8",
    )
    subprocess.run(["ollama", "create", OLLAMA_MODEL, "-f", str(modelfile)], check=True, cwd=str(gguf.parent))


def chat(messages: list[dict], timeout: int = 240) -> str:
    body = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "think": False,
            "keep_alive": "30m",
            "options": {"temperature": 0.2, "num_ctx": 2048, "num_predict": 200},
        }
    ).encode()
    req = Request(ollama_url() + "/api/chat", data=body, headers={"Content-Type": "application/json"}, method="POST")
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
    return content


if __name__ == "__main__":
    dest = lab_root() / "otlab-work" / "models" / "cyberpal-2.0-4b"
    path = download_gguf(dest)
    print("gguf", path)
    if ollama_ready():
        print("ollama", OLLAMA_MODEL, "already present")
    else:
        import_ollama(path)
        print("ollama", OLLAMA_MODEL, "ready" if ollama_ready() else "import failed")
