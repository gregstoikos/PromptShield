"""PromptShield: local, explainable prompt injection heuristics."""
from .detector import DetectionResult, PatternMatch, analyze

__all__ = ["DetectionResult", "PatternMatch", "analyze"]
