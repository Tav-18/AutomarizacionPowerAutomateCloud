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
    r"client[_-]?secret|private[_-]?key|sas|signature|sig=|access[_-]?key|"
    r"connectionstring|connection[_-]?string)",
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

WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")
UNIX_PATH_RE = re.compile(r"^/(?!/).+")
VARIABLE_NAME_RE = re.compile(r"^(Bln|Int|Flt|Str|Obj|Arr)[A-Z][A-Za-z0-9]*$")

PARAMETRIZABLE_PATH_HINTS = (
    ".uri",
    ".url",
    ".endpoint",
    ".path",
    ".route",
    ".folder",
    ".folderpath",
    ".filepath",
    ".file",
    ".filename",
    ".host",
    ".hostname",
    ".baseurl",
    ".base_url",
    ".siteaddress",
    ".server",
)

SYSTEM_VALUE_HINTS = (
    "schema.org",
    "w3.org",
    "powerautomate.com",
    "logic-apis",
    "swagger",
    "openapi",
)

DYNAMIC_REF_RE = re.compile(
    r"(@\{.*?\}|@\(|@parameters\(|@variables\(|@outputs\(|@trigger|@items\(|"
    r"\$\{.*?\}|%[^%]+%|workflow\(|triggerBody\(|items\(|outputs\(|variables\(|parameters\()",
    re.IGNORECASE
)


# =========================
# Model
# =========================

@dataclass
class Finding:
    # Se muestra en UI
    severity_level: int   # 1=bajo, 2=medio, 3=crítico
    rule_name: str        # Nombre legible

    # Identificación
    flow_name: str
    action_name: str
    json_path: str

    # Explicación
    reason: str
    evidence: str
    impact: str
    fix: str


# =========================
# Helpers
# =========================

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

    # Los correos ahora también se consideran sensibles
    if EMAIL_RE.search(text):
        return True

    return bool(
        SENSITIVE_KEYWORDS_RE.search(text)
        or SENSITIVE_URL_QUERY_RE.search(text)
    )


def _is_dynamic_reference(text: str) -> bool:
    if not text:
        return False

    s = text.strip()
    return (
        s.startswith("@")
        or "@{" in s
        or "@parameters(" in s
        or "@variables(" in s
        or "@outputs(" in s
        or "@trigger" in s
        or "@items(" in s
        or "triggerBody(" in s
        or "outputs(" in s
        or "items(" in s
        or "variables(" in s
        or "parameters(" in s
        or "%Env" in s
        or bool(DYNAMIC_REF_RE.search(s))
    )


def _is_system_value(text: str) -> bool:
    if not text:
        return False

    low = text.lower()
    return any(token in low for token in SYSTEM_VALUE_HINTS)

def _leaf_path_name(path: str) -> str:
    """
    Devuelve el nombre final del path.
    Ejemplo:
    definition.actions.Send_an_email_(V2).inputs.to -> to
    """
    if not path:
        return ""

    parts = path.split(".")
    if not parts:
        return ""

    leaf = parts[-1]
    leaf = re.sub(r"\[\d+\]$", "", leaf)
    return leaf.lower().strip()

def _dedupe_pairs(items: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    seen = set()
    out: List[Tuple[str, str]] = []

    for path, value in items:
        key = (path, value)
        if key not in seen:
            seen.add(key)
            out.append((path, value))

    return out


def _extract_initialized_variable_names(
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Tuple[str, str]]:
    """
    Intenta extraer nombres de variables en acciones relacionadas con variables.
    Es defensiva porque en Power Automate algunos inputs vienen como string y no como dict.
    """
    found: List[Tuple[str, str]] = []

    raw_inputs = action_raw.get("inputs")
    if not isinstance(raw_inputs, dict):
        return found

    inputs = raw_inputs
    action_type = str(action_raw.get("type", "") or "").lower()
    action_name_low = (action_name or "").lower()

    # Caso 1: estructura común inputs.variables[].name
    variables = inputs.get("variables")
    if isinstance(variables, list):
        for i, item in enumerate(variables):
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if name:
                    found.append((f"{base_path}.inputs.variables[{i}].name", name))

    # Caso 2: fallback heurístico solo para acciones que parezcan de variables
    looks_like_variable_action = (
        "variable" in action_type
        or "initialize_variable" in action_name_low
        or "set_variable" in action_name_low
    )

    if looks_like_variable_action:
        for key in ("name", "variableName", "variable", "nombre"):
            value = inputs.get(key)
            if isinstance(value, str) and value.strip():
                found.append((f"{base_path}.inputs.{key}", value.strip()))

    return _dedupe_pairs(found)

def _parent_path_name(path: str) -> str:
    """
    Devuelve el penúltimo nombre del path, si existe.
    """
    if not path:
        return ""

    parts = path.split(".")
    if len(parts) < 2:
        return ""

    parent = parts[-2]
    parent = re.sub(r"\[\d+\]$", "", parent)
    return parent.lower().strip()


def _looks_sensitive_literal(path: str, value: str) -> bool:
    value = (value or "").strip()

    if not value or _is_dynamic_reference(value):
        return False

    # Ignorar valores técnicos del sistema
    if _is_system_value(value):
        return False

    # 1) Todo correo literal sí entra como sensible
    if EMAIL_RE.search(value):
        return True

    # 2) Si el valor trae indicadores claros de secreto, sí entra
    if _classify_sensitivity(value):
        return True

    # 3) Revisar SOLO nombres reales del campo, no todo el path completo
    leaf = _leaf_path_name(path)
    parent = _parent_path_name(path)

    sensitive_fields = {
        "password", "passwd", "pwd",
        "secret", "token",
        "api_key", "apikey",
        "clientsecret", "client_secret",
        "privatekey", "private_key",
        "authorization",
        "accesskey", "access_key",
        "connectionstring", "connection_string",
        "correo", "email", "mail",
        "recipient", "recipients",
        "to", "cc", "bcc",
    }

    if leaf in sensitive_fields or parent in sensitive_fields:
        return True

    return False


def _looks_parametrizable_literal(path: str, value: str) -> bool:
    value = (value or "").strip()

    if not value:
        return False

    if _is_dynamic_reference(value):
        return False

    if EMAIL_RE.search(value):
        return False

    if _classify_sensitivity(value):
        return False

    if _is_system_value(value):
        return False

    leaf = _leaf_path_name(path)

    parametrizable_fields = {
        "uri", "url", "endpoint",
        "path", "route",
        "folder", "folderpath",
        "filepath", "file", "filename",
        "host", "hostname",
        "baseurl", "base_url",
        "siteaddress", "server",
    }

    if leaf not in parametrizable_fields:
        return False

    if URL_RE.search(value):
        return True

    if WINDOWS_PATH_RE.search(value) or UNIX_PATH_RE.search(value):
        return True

    if ("/" in value or "\\" in value or "." in value) and len(value) > 3:
        return True

    return False


# =========================
# Rules (Action level)
# =========================

def check_hardcode_and_parametrizable(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    """
    Separación:
    - Hardcode sensible -> nivel 3
    - Parametrizable -> nivel 2 para URLs/rutas/endpoints no sensibles
    """
    findings: List[Finding] = []

    raw_inputs = action_raw.get("inputs")

    if isinstance(raw_inputs, (dict, list, str)):
        walk_source = raw_inputs
    else:
        walk_source = {}

    for path, s in _walk_values(walk_source, f"{base_path}.inputs"):
        value = (s or "").strip()
        if not value:
            continue

        if _looks_sensitive_literal(path, value):
            findings.append(Finding(
                severity_level=3,
                rule_name="Hardcode sensible",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason="Se detectó un valor sensible hardcodeado dentro de inputs.",
                evidence=value[:240],
                impact="Riesgo de exposición de correos, credenciales, tokens o información sensible; además acopla el flujo a una configuración insegura.",
                fix="Mover este valor a un mecanismo seguro (por ejemplo Key Vault, connection reference o variable de entorno protegida) y resolverlo dinámicamente."
            ))
            continue

        if _looks_parametrizable_literal(path, value):
            findings.append(Finding(
                severity_level=2,
                rule_name="Parametrizable",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason="Se detectó un valor fijo no sensible (URL/ruta/endpoint/host) que debería parametrizarse.",
                evidence=value[:240],
                impact="Complica promoción entre ambientes, mantenimiento y cambios futuros.",
                fix="Mover este valor a un mecanismo parametrizable (variables de entorno, parámetros, connection references o configuración central)."
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
    - Nivel 2 si no existe runAfter
    """
    if action_raw.get("runAfter") is None:
        return [Finding(
            severity_level=2,
            rule_name="Manejo de errores (RunAfter)",
            flow_name=flow_name,
            action_name=action_name,
            json_path=f"{base_path}.runAfter",
            reason="La acción no define RunAfter; podría no manejar failed, timedOut o canceled.",
            evidence="runAfter no definido",
            impact="El flujo puede detenerse o comportarse de forma inesperada ante fallos o timeout sin ruta controlada.",
            fix="Configurar RunAfter para failed, timedOut o canceled en acciones relevantes y agregar manejo controlado."
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
    - Nivel 2 si se detecta Delay/Wait con valor literal
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
                    reason="Se detectó Delay o Wait con valor literal; puede degradar rendimiento y volver frágil el flujo.",
                    evidence=s[:240],
                    impact="Aumenta tiempos de ejecución y puede fallar si cambian tiempos o latencias del entorno.",
                    fix="Evitar delays innecesarios; si se requiere, justificar y parametrizar o usar una condición de espera más robusta."
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
    - Única severidad: nivel 1
    """
    findings: List[Finding] = []

    if NAMING_ALLOWLIST_RE.match(action_name):
        return findings

    # Si tiene "_-_" o "-" lo consideramos "personalizado"
    if "_-_" in action_name or "-" in action_name:
        if re.search(r"[áéíóúñÁÉÍÓÚÑ]", action_name):
            findings.append(Finding(
                severity_level=1,
                rule_name="Naming de actividades",
                flow_name=flow_name,
                action_name=action_name,
                json_path=base_path,
                reason="El nombre contiene acentos o ñ; se recomienda solo ASCII para consistencia.",
                evidence=f"Nombre: {action_name}",
                impact="Inconsistencia de estandarización y posibles diferencias entre equipos o entornos.",
                fix="Renombrar usando ASCII sin acentos ni caracteres especiales."
            ))
        return findings

    if DEFAULT_ACTION_NAME_RE.match(action_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Naming de actividades",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason="Se detectó un nombre por default (Compose, Condition, Apply_to_each, etc.).",
            evidence=f"Nombre: {action_name}",
            impact="Dificulta trazabilidad y mantenimiento porque no se entiende el propósito de la acción sin abrirla.",
            fix="Renombrar la acción con propósito claro, sin numeración innecesaria."
        ))

    if re.search(r"[áéíóúñÁÉÍÓÚÑ]", action_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Naming de actividades",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason="El nombre contiene acentos o ñ; se recomienda solo ASCII para consistencia.",
            evidence=f"Nombre: {action_name}",
            impact="Inconsistencia de estandarización y posibles diferencias entre equipos o entornos.",
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
            reason="Se detectó un nombre por default (Compose, Condition, Apply_to_each, etc.).",
            evidence=f"Nombre: {action_name}",
            impact="Dificulta trazabilidad y mantenimiento porque no se entiende el propósito de la acción sin abrirla.",
            fix="Renombrar la acción con propósito claro, sin numeración innecesaria."
        ))

    if re.search(r"[áéíóúñÁÉÍÓÚÑ]", action_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Naming de actividades",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason="El nombre contiene acentos o ñ; se recomienda solo ASCII para consistencia.",
            evidence=f"Nombre: {action_name}",
            impact="Inconsistencia de estandarización y posibles diferencias entre equipos o entornos.",
            fix="Renombrar usando ASCII sin acentos ni caracteres especiales."
        ))

    return findings
def check_variable_naming(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    """
    Regla: Nomenclatura de variables
    Formato esperado:
    Bln / Int / Flt / Str / Obj / Arr + UpperCamelCase
    Ejemplo válido:
    StrNombreCliente
    """
    findings: List[Finding] = []

    for path, var_name in _extract_initialized_variable_names(action_name, action_raw, base_path):
        if not VARIABLE_NAME_RE.match(var_name):
            findings.append(Finding(
                severity_level=1,
                rule_name="Nomenclatura de variables",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason="La variable no sigue la convención esperada de tipo + UpperCamelCase.",
                evidence=f"Variable: {var_name}",
                impact="Complica lectura del flujo y dificulta inferir rápidamente el tipo o propósito de la variable.",
                fix="Renombrar la variable usando prefijo de tipo (Bln/Int/Flt/Str/Obj/Arr) y un nombre descriptivo en UpperCamelCase."
            ))

    return findings

def run_all_rules(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_hardcode_and_parametrizable(flow_name, action_name, action_raw, base_path)
    findings += check_missing_runafter(flow_name, action_name, action_raw, base_path)
    findings += check_delay_usage(flow_name, action_name, action_raw, base_path)
    findings += check_action_naming_cloud(flow_name, action_name, base_path)
    findings += check_variable_naming(flow_name, action_name, action_raw, base_path)
    return findings