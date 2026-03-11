from typing import List, Tuple
from .rules import Finding

def compute_score(findings: List[Finding]) -> Tuple[int, int, int, int, str]:
    """
    severity_level:
    3 = crítico
    2 = medio
    1 = bajo
    """
    s3 = sum(1 for f in findings if f.severity_level == 3)
    s2 = sum(1 for f in findings if f.severity_level == 2)
    s1 = sum(1 for f in findings if f.severity_level == 1)

    # Ponderación (ajustable):
    # 3 crítico = -10
    # 2 medio   = -3
    # 1 bajo    = -1
    score = max(0, 100 - (10 * s3) - (3 * s2) - (1 * s1))

    if score >= 90:
        sem = "OK"
    elif score >= 75:
        sem = "Observaciones"
    else:
        sem = "No aprobable"

    return score, s3, s2, s1, sem