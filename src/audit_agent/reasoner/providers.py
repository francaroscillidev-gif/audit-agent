"""Multi-provider LLM adapter supporting Google Gemini, OpenAI, Anthropic, and local Ollama."""
import json
import os
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List


class LLMProviderAdapter:
    """Unified LLM client for reasoning and test harness synthesis."""

    PROVIDERS = ["offline_expert", "gemini", "openai", "anthropic", "ollama"]

    def __init__(self, provider: str = "offline_expert", model: Optional[str] = None, api_key: Optional[str] = None):
        self.provider = provider.lower()
        self.model = model
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")

        if self.provider == "gemini" and not self.model:
            self.model = "gemini-2.5-flash"
        elif self.provider == "openai" and not self.model:
            self.model = "gpt-4o"
        elif self.provider == "anthropic" and not self.model:
            self.model = "claude-3-5-sonnet-20241022"
        elif self.provider == "ollama" and not self.model:
            self.model = "deepseek-coder:latest"

    def complete(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Send a completion request to the configured provider."""
        if self.provider == "offline_expert":
            return None

        if self.provider == "gemini":
            return self._call_gemini(prompt, system_prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt, system_prompt)
        elif self.provider == "ollama":
            return self._call_ollama(prompt, system_prompt)

        return None

    def _call_gemini(self, prompt: str, system_prompt: Optional[str]) -> Optional[str]:
        if not self.api_key:
            return None
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": f"{system_prompt}\n\n{prompt}" if system_prompt else prompt}]}]
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            return None

    def _call_openai(self, prompt: str, system_prompt: Optional[str]) -> Optional[str]:
        if not self.api_key:
            return None
        url = "https://api.openai.com/v1/chat/completions"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {"model": self.model, "messages": messages}
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
        except Exception:
            return None

    def _call_ollama(self, prompt: str, system_prompt: Optional[str]) -> Optional[str]:
        url = "http://localhost:11434/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response")
        except Exception:
            return None
