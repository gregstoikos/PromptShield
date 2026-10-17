"""Pure-Python detection with deterministic, bounded scoring."""
import re
import unicodedata
from dataclasses import asdict, dataclass

from .patterns import RULES

MAX_INPUT_LENGTH = 50_000
_COMPILED_RULES = tuple((rule, re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)) for rule in RULES)


@dataclass(frozen=True)
class PatternMatch:
    rule_id: str
    category: str
    weight: int
    explanation: str
    evidence: str


@dataclass(frozen=True)
class DetectionResult:
    score: int
    level: str
    matches: tuple[PatternMatch, ...]

    def to_dict(self) -> dict:
        """Return JSON-serializable results."""
        return asdict(self)


def normalize(text: str) -> str:
    """Normalize Unicode width and remove invisible format characters."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(char for char in text if unicodedata.category(char) != "Cf")


def analyze(text: str) -> DetectionResult:
    """Scan text; each rule contributes once, regardless of repetition.

    Evidence is from normalized text, not character offsets in the original.
    Category contributions are capped at 50; the total is capped at 100.
    """
    if not isinstance(text, str):
        raise TypeError("Prompt must be a string.")
    if len(text) > MAX_INPUT_LENGTH:
        raise ValueError(f"Prompt must be at most {MAX_INPUT_LENGTH:,} characters.")
    normalized = normalize(text)
    if len(normalized) > MAX_INPUT_LENGTH:
        raise ValueError("Normalized prompt exceeds the input limit.")
    matches = []
    categories: dict[str, int] = {}
    for rule, regex in _COMPILED_RULES:
        match = regex.search(normalized)
        if match:
            matches.append(PatternMatch(rule.id, rule.category, rule.weight,
                                        rule.explanation, match.group(0)))
            categories[rule.category] = min(50, categories.get(rule.category, 0) + rule.weight)
    score = min(100, sum(categories.values()))
    level = "Low" if score < 30 else "Medium" if score < 60 else "High"
    return DetectionResult(score, level, tuple(matches))
