from app.modules.rag.mitre import get_mitre_kb


def test_mitre_retrieval_brute_force():
    kb = get_mitre_kb()
    results = kb.retrieve("failed login brute force password")
    assert len(results) >= 1
    assert results[0].technique_id == "T1110"
