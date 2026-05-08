"""Semantic feature extraction — parameter and context embeddings.

Encodes tool call parameters and surrounding context into dense vectors
for use by the detection engine. Uses category-aware embeddings with
character n-gram feature hashing for semantic similarity.
"""

from __future__ import annotations

import functools
import math
import numpy as np
from dataclasses import dataclass

from callisto.collector.models import CallEvent

# Semantic category mapping — tools that do similar things share a category,
# so their embeddings will be close in vector space.
TOOL_CATEGORIES: dict[str, str] = {
    "exec": "execution",
    "shell": "execution",
    "run_command": "execution",
    "write_file": "file_write",
    "delete_file": "file_write",
    "read_file": "file_read",
    "list_files": "file_read",
    "search": "file_read",
    "get_info": "info_retrieval",
    "summarize": "info_retrieval",
    "http_request": "network",
    "curl": "network",
    "send_email": "communication",
}

_CATEGORY_LIST = sorted(set(TOOL_CATEGORIES.values())) + ["unknown"]
_CATEGORY_INDEX: dict[str, int] = {c: i for i, c in enumerate(_CATEGORY_LIST)}
_NUM_CATEGORIES = len(_CATEGORY_LIST)


@dataclass
class SemanticFeatures:
    """Semantic embedding for a single call event."""

    tool_embedding: np.ndarray  # one-hot or learned tool ID embedding
    param_embedding: np.ndarray  # parameter content embedding
    combined: np.ndarray  # concatenated final vector

    def to_vector(self) -> np.ndarray:
        return self.combined


def _char_trigrams(text: str) -> list[str]:
    """Extract character 3-grams from a string."""
    padded = f"#{text}#"
    return [padded[i:i + 3] for i in range(len(padded) - 2)]


def _feature_hash(trigrams: list[str], size: int) -> np.ndarray:
    """Hash a list of trigrams into a fixed-size vector using dual hashing."""
    vec = np.zeros(size, dtype=np.float32)
    for gram in trigrams:
        # Primary hash for bucket index
        h = hash(gram) % size
        # Secondary hash for sign (+1 / -1) to reduce collisions
        sign = 1.0 if hash(gram + "_sign") % 2 == 0 else -1.0
        vec[h] += sign
    return vec


class SemanticExtractor:
    """Semantic feature extractor using category embeddings and n-gram hashing.

    Produces dense vectors where semantically similar tools (e.g. exec,
    shell, run_command) get nearby embeddings, unlike the old MD5/SHA256
    approach which produced cryptographically random vectors.
    """

    def __init__(self, embedding_dim: int = 64, known_tools: list[str] | None = None):
        self.embedding_dim = embedding_dim
        self._tool_vocab: dict[str, int] = {}
        if known_tools:
            for i, t in enumerate(known_tools):
                self._tool_vocab[t] = i

    @functools.lru_cache(maxsize=64)
    def _tool_to_vec(self, tool_name: str) -> np.ndarray:
        """Category-aware tool embedding with n-gram differentiation."""
        target = self.embedding_dim // 2
        vec = np.zeros(target, dtype=np.float32)

        # --- Part 1: one-hot category encoding ---
        category = TOOL_CATEGORIES.get(tool_name, "unknown")
        cat_idx = _CATEGORY_INDEX[category]
        cat_slots = min(_NUM_CATEGORIES, target)
        vec[cat_idx % cat_slots] = 1.0

        # --- Part 2: character 3-gram feature hashing for within-category differentiation ---
        remaining = target - cat_slots
        if remaining > 0:
            trigrams = _char_trigrams(tool_name)
            gram_vec = _feature_hash(trigrams, remaining)
            vec[cat_slots:] = gram_vec

        # Normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-9:
            vec /= norm
        return vec

    def _params_to_vec(self, params: dict) -> np.ndarray:
        """Semantic parameter embedding using typed feature hashing."""
        target = self.embedding_dim // 2
        vec = np.zeros(target, dtype=np.float32)

        half = target // 2
        key_size = max(half, 1)
        val_size = max(target - key_size, 1)

        key_vec = np.zeros(key_size, dtype=np.float32)
        val_vec = np.zeros(val_size, dtype=np.float32)

        for key, value in params.items():
            # Feature-hash parameter keys via character 3-grams
            key_trigrams = _char_trigrams(key)
            key_vec += _feature_hash(key_trigrams, key_size)

            # Type-aware value encoding
            if isinstance(value, bool):
                # Booleans: fixed positions based on key hash
                pos = hash(key) % val_size
                val_vec[pos] += 1.0 if value else -1.0
            elif isinstance(value, (int, float)):
                # Numerics: log-scaled magnitude bins
                magnitude = math.log1p(abs(float(value)))
                sign = 1.0 if value >= 0 else -1.0
                bin_idx = int(magnitude) % val_size
                val_vec[bin_idx] += sign * (1.0 + magnitude * 0.1)
            elif isinstance(value, str):
                # Strings: character 3-gram hashing
                str_trigrams = _char_trigrams(value)
                val_vec += _feature_hash(str_trigrams, val_size)
            # Other types (lists, dicts, None) are skipped

        vec[:key_size] = key_vec
        vec[key_size:key_size + val_size] = val_vec

        # Normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-9:
            vec /= norm
        return vec

    def extract_event(self, event: CallEvent) -> SemanticFeatures:
        tool_vec = self._tool_to_vec(event.tool_name)
        param_vec = self._params_to_vec(event.parameters)
        combined = np.concatenate([tool_vec, param_vec])
        return SemanticFeatures(
            tool_embedding=tool_vec,
            param_embedding=param_vec,
            combined=combined,
        )

    def extract_sequence(self, events: list[CallEvent]) -> np.ndarray:
        """Extract embeddings for a sequence, return (N, embedding_dim) array."""
        if not events:
            return np.zeros((0, self.embedding_dim))
        vecs = [self.extract_event(e).to_vector() for e in events]
        return np.stack(vecs)

    def extract_session_summary(self, events: list[CallEvent]) -> np.ndarray:
        """Aggregate session-level semantic summary (mean pooling)."""
        seq = self.extract_sequence(events)
        if len(seq) == 0:
            return np.zeros(self.embedding_dim)
        return seq.mean(axis=0)
