"""OpenAI-compatible client for the description LLM check (D6-44).

Implements ``mcp_guard.description_llm.DescriptionReviewer``. Plain http is
allowed only to a loopback host or a name the operator lists (a private Docker
network); anything else must be https. Redirects are refused, so a model
endpoint cannot bounce the description elsewhere.
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.request
from urllib.parse import urlparse


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise OSError("model endpoint redirected")


class OpenAICompatibleReviewer:
    def __init__(self, base_url: str, model: str, *, timeout: float = 120.0,
                 api_key_env: str = "", http_hosts: tuple[str, ...] = (),
                 classifier_floor: float | None = None) -> None:
        url = urlparse(base_url)
        if url.scheme not in {"http", "https"} or not url.hostname:
            raise ValueError("description LLM base URL must be an http(s) URL")
        if url.scheme == "http" and not _loopback(url.hostname) and url.hostname not in http_hosts:
            raise ValueError("plain http is allowed only to loopback or listed hosts")
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model, self._timeout, self._key_env = model, timeout, api_key_env
        self._opener = urllib.request.build_opener(_NoRedirect)
        self.model_id = f"{model}@{url.hostname}"
        # Staged check: with the B classifier on, descriptions scoring below this
        # are not sent to the model (mcp_guard.policy).
        if classifier_floor is not None and not 0 <= classifier_floor <= 1:
            raise ValueError("classifier_floor must be between 0 and 1")
        self.classifier_floor = classifier_floor

    def complete(self, messages: list[dict[str, str]]) -> str:
        headers = {"Content-Type": "application/json", "User-Agent": "mcp-guard-description-check/0.1"}
        if self._key_env:
            headers["Authorization"] = f"Bearer {os.environ[self._key_env]}"
        body = json.dumps({"model": self._model, "messages": messages, "temperature": 0,
                           "response_format": {"type": "json_object"}}).encode()
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        with self._opener.open(request, timeout=self._timeout) as response:
            return json.loads(response.read(2_000_000))["choices"][0]["message"]["content"]


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
