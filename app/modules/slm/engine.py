import time
from typing import Any

from app.config import get_settings
from app.core.prompt_filter import detect_prompt_injection, sanitize_for_slm
from app.modules.rag.mitre import get_mitre_kb
from app.modules.slm.templates import format_incident_report
from app.modules.threat_detection.rules import RuleMatch


class SLMEngine:
    """Template-first SLM with optional Hugging Face local inference."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._hf_pipeline = None

    @property
    def mode(self) -> str:
        return self.settings.slm_mode

    def _load_huggingface(self) -> Any:
        if self._hf_pipeline is not None:
            return self._hf_pipeline
        try:
            from transformers import pipeline  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "Hugging Face mode requires: pip install torch transformers accelerate"
            ) from exc

        self._hf_pipeline = pipeline(
            "text-generation",
            model=self.settings.slm_model_name,
            device_map=self.settings.slm_device,
            max_new_tokens=self.settings.slm_max_tokens,
        )
        return self._hf_pipeline

    def _hf_generate(self, prompt: str) -> str:
        pipe = self._load_huggingface()
        out = pipe(prompt, do_sample=False, temperature=0.2, return_full_text=False)
        text = out[0]["generated_text"] if out else ""
        return text.strip()

    def _build_prompt(self, match: RuleMatch, log_text: str) -> str:
        return (
            "You are a cybersecurity analyst assistant. Analyze the security log and threat.\n"
            f"Threat: {match.threat_type}\n"
            f"Rule: {match.rule_id}\n"
            f"Log:\n{sanitize_for_slm(log_text)}\n\n"
            "Respond with: Threat Type, Severity, Explanation (2-3 sentences), "
            "and 4 numbered Recommended Actions."
        )

    def analyze(self, match: RuleMatch, log_text: str) -> dict[str, Any]:
        injected, pattern = detect_prompt_injection(log_text)
        if injected:
            return {
                "threat_type": match.threat_type,
                "severity": match.severity.value,
                "explanation": (
                    "Analysis blocked: potential prompt injection detected in log content. "
                    f"Matched pattern: {pattern}"
                ),
                "recommendations": [
                    "Quarantine this log entry for manual review",
                    "Do not pass untrusted log fields directly to cloud LLMs",
                    "Sanitize log pipelines before AI enrichment",
                ],
                "slm_mode": "blocked",
            }

        if self.mode == "huggingface":
            try:
                generated = self._hf_generate(self._build_prompt(match, log_text))
                return {
                    "threat_type": match.threat_type,
                    "severity": match.severity.value,
                    "explanation": generated,
                    "recommendations": format_incident_report(match, log_text)["recommendations"],
                    "slm_mode": "huggingface",
                }
            except Exception:
                pass

        report = format_incident_report(match, log_text)
        explanation = report["explanation"]
        mitre_techniques: list[dict[str, str]] = []

        if self.settings.enable_mitre_rag:
            kb = get_mitre_kb()
            techniques = kb.retrieve(f"{match.threat_type} {log_text}")
            mitre_techniques = [
                {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
                for t in techniques
            ]
            if techniques:
                explanation = f"{explanation}\n\n{kb.format_context(techniques)}"

        return {
            **report,
            "explanation": explanation,
            "mitre_techniques": mitre_techniques,
            "slm_mode": "template",
        }

    def chat(self, question: str, context: str) -> str:
        injected, _ = detect_prompt_injection(question)
        if injected:
            return "Request blocked due to potential prompt injection."

        q = question.lower()
        if "severity" in q or "why" in q:
            return (
                f"Based on stored analysis context:\n{sanitize_for_slm(context, 4000)}\n\n"
                "Severity reflects rule confidence, asset sensitivity (e.g. admin account), "
                "and attack class per internal playbooks."
            )
        if "mitigation" in q or "recommend" in q:
            return (
                "Follow the numbered recommendations in the alert. "
                "Prioritize containment, then eradication, then recovery per NIST IR phases."
            )
        return (
            "Secure-SLM chat is context-limited to the selected alert. "
            "Ask about severity, threat type, or recommended mitigations."
        )


_slm: SLMEngine | None = None


def get_slm_engine() -> SLMEngine:
    global _slm
    if _slm is None:
        _slm = SLMEngine()
    return _slm


def analyze_with_timing(match: RuleMatch, log_text: str) -> tuple[dict[str, Any], int]:
    start = time.perf_counter()
    result = get_slm_engine().analyze(match, log_text)
    ms = int((time.perf_counter() - start) * 1000)
    return result, ms
