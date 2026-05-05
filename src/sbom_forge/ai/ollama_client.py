import httpx
from typing import Dict, Optional

DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"


class OllamaClient:
    def __init__(self, base_url: str = DEFAULT_OLLAMA_URL, model: str = "llama3.1"):
        self.base_url = base_url
        self.model = model

    def is_available(self) -> bool:
        try:
            version_url = self.base_url.replace("/api/generate", "/api/version")
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(version_url)
                return resp.status_code == 200
        except Exception:
            return False

    def generate_reasoning(self, prompt: str, system_prompt: str) -> Optional[str]:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,  # Low temperature for deterministic security reasoning
                "top_p": 0.9,
            },
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(self.base_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("response")
        except Exception:
            pass

        return None
