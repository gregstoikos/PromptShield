"""Auditable rules. Add a Rule here to extend the detector."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: str
    weight: int
    explanation: str


RULES = (
    Rule("override_ignore", "Instruction override", r"\b(?:ignore|disregard|forget)\b.{0,50}\b(?:previous|prior|above|all|system)\b.{0,30}\b(?:instructions?|rules?|prompts?)\b", 35,
         "Asks the assistant to discard existing instructions or rules."),
    Rule("override_replace", "Instruction override", r"\b(?:override|bypass|disable)\b.{0,45}\b(?:instructions?|rules?|safety|guardrails?|restrictions?)\b", 35,
         "Requests bypassing instruction or safety boundaries."),
    Rule("extract_prompt", "System prompt extraction", r"\b(?:reveal|show|print|repeat|output|expose|display|give\s+me)\b.{0,60}\b(?:system|developer|hidden|initial)\s+(?:prompt|instructions?|message)s?\b", 40,
         "Requests disclosure of hidden system or developer instructions."),
    Rule("extract_verbatim", "System prompt extraction", r"\b(?:repeat|copy|print|output)\b.{0,40}\b(?:everything|all\s+(?:the\s+)?(?:text|instructions?))\b.{0,30}\b(?:above|before)\b", 30,
         "Attempts to recover preceding context, which may contain private instructions."),
    Rule("role_delimiter", "Role spoofing", r"(?:<\|(?:im_start|start_header_id)\|>\s*(?:system|developer|assistant)\b|\[\s*(?:system|developer)\s*\]|</?(?:system|developer)\s*>|(?:^|\n)\s*(?:system|developer)\s*:)", 35,
         "Uses privileged role labels or chat delimiters to impersonate trusted messages."),
    Rule("role_claim", "Role spoofing", r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\b.{0,40}\b(?:system|developer|unrestricted|DAN|administrator)\b", 30,
         "Claims a privileged or unrestricted role for the assistant."),
    Rule("exfil_send", "Data exfiltration", r"\b(?:send|upload|post|transmit|forward|exfiltrate)\b.{0,100}\b(?:secrets?|passwords?|tokens?|api[ _-]?keys?|credentials?|private\s+data|conversation(?:\s+history)?)\b.{0,100}\b(?:https?://|webhook\b|email\b|[\w.+-]+@[\w.-]+\.[a-z]{2,})", 50,
         "Directs sensitive information to an external URL, webhook, or email destination."),
    Rule("exfil_destination_first", "Data exfiltration", r"\b(?:send|upload|post|transmit|forward|exfiltrate)\b.{0,60}(?:https?://[^\s]+|webhook\b|email\b).{0,100}\b(?:secrets?|passwords?|tokens?|api[ _-]?keys?|credentials?|private\s+data|conversation(?:\s+history)?)\b", 50,
         "Names an external destination before requesting sensitive data transfer."),
    Rule("exfil_encode", "Data exfiltration", r"\b(?:encode|base64|encrypt)\b.{0,70}\b(?:secrets?|credentials?|tokens?|api[ _-]?keys?|system\s+prompt)\b.{0,70}\b(?:send|upload|post|transmit|forward)\b", 45,
         "Combines encoding of sensitive content with a transfer instruction."),
)
