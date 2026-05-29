import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    keywords: list[str]
    score: float = 0.0


class MitreKnowledgeBase:
    def __init__(self, data_path: Path | None = None) -> None:
        path = data_path or Path(__file__).resolve().parents[3] / "data" / "mitre_attack.json"
        self.techniques: list[MitreTechnique] = []
        with path.open(encoding="utf-8") as f:
            raw = json.load(f)
        for item in raw:
            self.techniques.append(MitreTechnique(**item))

    def retrieve(self, query: str, top_k: int = 2) -> list[MitreTechnique]:
        lower = query.lower()
        scored: list[MitreTechnique] = []
        for tech in self.techniques:
            score = 0.0
            for kw in tech.keywords:
                if kw in lower:
                    score += 2.0
            if tech.name.lower() in lower:
                score += 1.5
            if tech.technique_id.lower() in lower:
                score += 1.0
            if score > 0:
                scored.append(
                    MitreTechnique(
                        technique_id=tech.technique_id,
                        name=tech.name,
                        tactic=tech.tactic,
                        description=tech.description,
                        keywords=tech.keywords,
                        score=score,
                    )
                )
        scored.sort(key=lambda t: t.score, reverse=True)
        return scored[:top_k]

    def format_context(self, techniques: list[MitreTechnique]) -> str:
        if not techniques:
            return ""
        lines = ["MITRE ATT&CK context:"]
        for t in techniques:
            lines.append(
                f"- {t.technique_id} {t.name} ({t.tactic}): {t.description}"
            )
        return "\n".join(lines)


_kb: MitreKnowledgeBase | None = None


def get_mitre_kb() -> MitreKnowledgeBase:
    global _kb
    if _kb is None:
        _kb = MitreKnowledgeBase()
    return _kb
