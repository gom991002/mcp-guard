"""Optional Horizon Labs prompt-injection classifier for B signals.

Weights live in the Hugging Face cache, never in this repository. The core
does not import torch or transformers unless the operator enables this module.
"""

from __future__ import annotations

from typing import Any

MODEL_ID = "Horizon-Labs/prompt-injection-guard-small"
MODEL_REVISION = "5ed691c28fc37db51f4e80fb81311b7d2b5d4646"


class PromptGuardClassifier:
    def __init__(self, model_id: str = MODEL_ID, revision: str | None = MODEL_REVISION,
                 max_tokens: int = 2048, stride: int = 512,
                 local_files_only: bool = False, backend: str = "onnx") -> None:
        if not 2 <= max_tokens <= 8192 or not 0 <= stride < max_tokens:
            raise ValueError("max_tokens must be 2..8192 and stride must be smaller")
        if backend != "onnx":
            raise ValueError("only the tested ONNX backend is supported")
        try:
            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from transformers import AutoConfig, AutoTokenizer
        except ImportError as error:
            raise RuntimeError("Prompt Injection Guard needs transformers, huggingface_hub and onnxruntime") from error
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_id, revision=revision, local_files_only=local_files_only)
        config = AutoConfig.from_pretrained(
            model_id, revision=revision, local_files_only=local_files_only)
        weights = hf_hub_download(model_id, "onnx/model_quantized.onnx",
                                  revision=revision, local_files_only=local_files_only)
        self._session = ort.InferenceSession(weights, providers=["CPUExecutionProvider"])
        self._input_names = {item.name for item in self._session.get_inputs()}
        self._window = max_tokens
        self._stride = stride
        self._injection = _injection_index(config.id2label)
        self.model_id = model_id
        self.revision = revision or getattr(config, "_commit_hash", None) or ""

    def score(self, text: str) -> float:
        """Largest INJECTION probability over overlapping windows, 0-1."""
        encoded = self._tokenizer(
            text, truncation=True, max_length=self._window, stride=self._stride,
            return_overflowing_tokens=True, padding=True, return_tensors="np",
        )
        encoded.pop("overflow_to_sample_mapping", None)
        import numpy as np
        logits = self._session.run(None, {name: value for name, value in encoded.items()
                                          if name in self._input_names})[0]
        shifted = logits - logits.max(axis=-1, keepdims=True)
        probabilities = np.exp(shifted) / np.exp(shifted).sum(axis=-1, keepdims=True)
        return float(probabilities[:, self._injection].max())


def _injection_index(id2label: dict[Any, str]) -> int:
    matches = [int(index) for index, label in id2label.items()
               if str(label).upper() == "INJECTION"]
    if len(matches) != 1:
        raise ValueError("model must have exactly one INJECTION label")
    return matches[0]
