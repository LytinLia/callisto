"""
CALLISTO - Security Detection System for LLM Agents

A comprehensive security framework for detecting and preventing
malicious activities in tool-augmented language model agents.
"""

__version__ = "2.0.0"
__author__ = "CALLISTO Team"

from .engine import CallistoEngine
from .config import CallistoConfig
from .sanitizer import Sanitizer

__all__ = [
    "CallistoEngine",
    "CallistoConfig",
    "Sanitizer",
]
