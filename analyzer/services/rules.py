import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


# =========================
# Patterns (Cloud)
# =========================

URL_RE = re.compile(r"https?://", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", re.IGNORECASE)

SENSITIVE_KEYWORDS_RE = re.compile(
    r"(api[_-]?key|secret|password|passwd|pwd|token|bearer|authorization|"
    r"client[_-]?secret|private[_-]?key|sas|signature|sig=|access[_-]?key)",
    re.IGNORECASE
)

SENSITIVE_URL_QUERY_RE = re.compile(
    r"(\?|&)(token|api[_-]?key|key|secret|sig|signature|sas|access[_-]?key|auth)=",
    re.IGNORECASE
)

DEFAULT_ACTION_NAME_RE = re.compile(
    r"^(Compose|Compose_\d+|Initialize_variable|Initialize_variable_\d+|"
    r"Condition|Condition_\d+|Apply_to_each|Apply_to_each_\d+|"
    r"Scope|Scope_\d+|Switch|Switch_\d+)$",
    re.IGNORECASE
)

NAMING_ALLOWLIST_RE = re.compile(
    r"^(When_a_HTTP_request_is_received|Recurrence)$",
    re.IGNORECASE
)

DELAY_NAME_RE = re.compile(r"\b(delay|wait)\b", re.IGNORECASE)


# =========================
# Model
# =========================

@dataclass
class Finding:
    # Se muestra en UI
    severity_level: int   # 1=bajo, 2=medio, 3=crítico
    rule_name: str        # Nombre legible (Hardcode, Naming, etc.)

    # Identificación
    flow_name: str
    action_name: str
    json_path: str

    # Explicación
    reason: str
    evidence: str
    impact: str
    fix: str


def _walk_values(obj: Any, base_path: str) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            found.extend(_walk_values(v, f"{base_path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_walk_values(v, f"{base_path}[{i}]"))
    elif isinstance(obj, str):
        found.append((base_path, obj))
    return found


def _classify_sensitivity(text: str) -> bool:
    if not text:
        return False
    return bool(SENSITIVE_KEYWORDS_RE.search(text) or SENSITIVE_URL_QUERY_RE.search(text))


# =========================
# Rules (Cloud only)
# =========================

def check_hardcoded_urls_emails(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    """
    Regla: Hardcode (URL/Email)
    - Nivel 2 por default (medio)
    - Nivel 3 si detecta datos sensibles (token/key/secret/bearer, etc.)
    """
    findings: List[Finding] = []

    fix_cloud = (
        "Parametrizar en Cloud (Environment Variables / Dataverse / SharePoint List / Key Vault, "
        "según el estándar de la empresa) y referenciar dinámicamente."
    )

    for path, s in _walk_values(action_raw.get("inputs", {}), f"{base_path}.inputs"):
        # URL literal
        if URL_RE.search(s):
            is_sensitive = _classify_sensitivity(s)
            severity_level = 3 if is_sensitive else 2

            findings.append(Finding(
                severity_level=severity_level,
                rule_name="Hardcode (URL/Email)",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason=(
                    "Se detectó una URL literal dentro de inputs. "
                    + ("Contiene indicadores de información sensible (token/key/secret)." if is_sensitive
                    else "Se recomienda parametrizar por ambiente/configuración.")
                ),
                evidence=s[:240],
                impact=(
                    "URL fija en el flujo; puede romperse por ambiente/cambios. "
                    + ("Riesgo alto: posible exposición o acoplamiento de credenciales/tokens." if is_sensitive
                    else "Riesgo: mantenimiento y consistencia entre ambientes.")
                ),
                fix=fix_cloud
            ))

        # Email literal
        if EMAIL_RE.search(s):
            severity_level = 2
            findings.append(Finding(
                severity_level=severity_level,
                rule_name="Hardcode (URL/Email)",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason="Se detectó un correo literal en inputs; debe administrarse por configuración/variables.",
                evidence=s[:240],
                impact="Correo hardcodeado; dificulta mantenimiento y puede generar envíos incorrectos por ambiente.",
                fix=fix_cloud
            ))

    return findings


def check_missing_runafter(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    """
    Regla: Manejo de errores (RunAfter)
    - Nivel 2 (medio) si no existe runAfter.
    """
    if action_raw.get("runAfter") is None:
        return [Finding(
            severity_level=2,
            rule_name="Manejo de errores (RunAfter)",
            flow_name=flow_name,
            action_name=action_name,
            json_path=f"{base_path}.runAfter",
            reason="La acción no define RunAfter; podría no manejar failed/timedOut/canceled.",
            evidence="runAfter no definido",
            impact="El flujo puede detenerse o comportarse de forma inesperada ante fallos/timeout sin ruta controlada.",
            fix="Configurar Run after para failed/timedOut/canceled en acciones relevantes y agregar manejo (log/notify/terminate controlado)."
        )]
    return []


def check_delay_usage(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    """
    Regla: Delay/Wait
    - Nivel 2 (medio) si se detecta Delay/Wait con valor literal.
    """
    findings: List[Finding] = []
    action_type = str(action_raw.get("type", "") or "")

    if DELAY_NAME_RE.search(action_name) or action_type.lower() == "delay":
        for path, s in _walk_values(action_raw.get("inputs", {}), f"{base_path}.inputs"):
            if re.search(r"\b\d+\b", s) or re.search(r"PT\d", s):
                findings.append(Finding(
                    severity_level=2,
                    rule_name="Delay/Wait",
                    flow_name=flow_name,
                    action_name=action_name,
                    json_path=path,
                    reason="Se detectó Delay/Wait con valor literal; puede degradar rendimiento y volver frágil el flujo.",
                    evidence=s[:240],
                    impact="Aumenta tiempos de ejecución y puede fallar si cambian tiempos/latencias del entorno.",
                    fix="Evitar delays innecesarios; si se requiere, justificar y parametrizar (variable/env) o usar condición de espera más robusta."
                ))
                break

    return findings


def check_action_naming_cloud(
    flow_name: str,
    action_name: str,
    base_path: str
) -> List[Finding]:
    """
    Regla: Naming de actividades
    - Nivel 1 (bajo) si contiene acentos/ñ
    - Nivel 2 (medio) si el nombre es default real (Compose, Condition_2, etc.)
    """
    findings: List[Finding] = []

    if NAMING_ALLOWLIST_RE.match(action_name):
        return findings

    # Si tiene "_-_" o "-" lo consideramos "personalizado" (evita falsos positivos)
    if "_-_" in action_name or "-" in action_name:
        # pero si trae acentos/ñ, sí lo reportamos como nivel 1
        if re.search(r"[áéíóúñÁÉÍÓÚÑ]", action_name):
            findings.append(Finding(
                severity_level=1,
                rule_name="Naming de actividades",
                flow_name=flow_name,
                action_name=action_name,
                json_path=base_path,
                reason="El nombre contiene acentos/ñ; se recomienda solo ASCII para consistencia.",
                evidence=f"Nombre: {action_name}",
                impact="Inconsistencia de estandarización y potenciales diferencias entre equipos/entornos.",
                fix="Renombrar usando ASCII sin acentos ni caracteres especiales."
            ))
        return findings

    if DEFAULT_ACTION_NAME_RE.match(action_name):
        findings.append(Finding(
            severity_level=2,
            rule_name="Naming de actividades",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason="Se detectó un nombre por default (Compose/Condition/Apply_to_each/etc.).",
            evidence=f"Nombre: {action_name}",
            impact="Dificulta trazabilidad y mantenimiento (no se entiende el propósito de la acción sin abrirla).",
            fix="Renombrar la acción con propósito claro (verbo + objeto), sin numeración."
        ))

    if re.search(r"[áéíóúñÁÉÍÓÚÑ]", action_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Naming de actividades",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason="El nombre contiene acentos/ñ; se recomienda solo ASCII para consistencia.",
            evidence=f"Nombre: {action_name}",
            impact="Inconsistencia de estandarización y potenciales diferencias entre equipos/entornos.",
            fix="Renombrar usando ASCII sin acentos ni caracteres especiales."
        ))

    return findings


def run_all_rules(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_hardcoded_urls_emails(flow_name, action_name, action_raw, base_path)
    findings += check_missing_runafter(flow_name, action_name, action_raw, base_path)
    findings += check_delay_usage(flow_name, action_name, action_raw, base_path)
    findings += check_action_naming_cloud(flow_name, action_name, base_path)
    return findings