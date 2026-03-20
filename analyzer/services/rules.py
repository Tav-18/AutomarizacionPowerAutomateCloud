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

ACCENTS_RE = re.compile(r"[áéíóúÁÉÍÓÚñÑ]")
DISALLOWED_CHARS_RE = re.compile(r"[#¿\?/\\:;\*<>\[\]\$&\+%{}]")
WRITING_BAD_CHARS_RE = re.compile(r"[#¿¡\{\}\[\]\|\\<>]")
FLOW_ALLOWED_RE = re.compile(r"^[A-Za-z0-9_\- ]+$")
WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:\\")
UNIX_PATH_RE = re.compile(r"^/(?!/).+")
UPPER_CAMEL_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
VARIABLE_NAME_RE = re.compile(r"^(Bln|Int|Flt|Str|Obj|Arr)[A-Z][A-Za-z0-9]*$")
PARAM_NAME_RE = re.compile(r"^(in|out|io)_(Bln|Int|Flt|Str|Obj|Arr)[A-Z][A-Za-z0-9]*$")

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
    ".dataset",
    ".table",
    ".server",
)

SYSTEM_PARAM_NAMES = {
    "$authentication",
    "$connections",
    "$schema",
    "authentication",
    "headers",
    "queries",
    "host",
    "path",
    "body",
}

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


def _is_custom_parameter_name(name: str) -> bool:
    if not name:
        return False

    low = name.strip().lower()

    if low in SYSTEM_PARAM_NAMES:
        return False
    if low.startswith("$"):
        return False
    if low.startswith("_"):
        return False

    return True


def _has_writing_issues(name: str) -> List[str]:
    issues: List[str] = []
    if not name:
        return issues

    if ACCENTS_RE.search(name):
        issues.append("contiene acentos o ñ")

    if WRITING_BAD_CHARS_RE.search(name):
        issues.append("contiene caracteres especiales no permitidos")

    return issues


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
    Primera versión:
    - intenta detectar variables inicializadas en inputs.variables[].name
    - y algunos campos comunes tipo inputs.name / inputs.variableName

    Nota:
    En Power Automate algunas acciones traen `inputs` como string,
    no como dict. Por eso primero validamos el tipo.
    """
    found: List[Tuple[str, str]] = []

    action_type = str(action_raw.get("type", "") or "").lower()
    raw_inputs = action_raw.get("inputs")

    if not isinstance(raw_inputs, dict):
        return found

    inputs = raw_inputs

    variables = inputs.get("variables")
    if isinstance(variables, list):
        for i, item in enumerate(variables):
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if name:
                    found.append((f"{base_path}.inputs.variables[{i}].name", name))

    # fallback heurístico
    if "variable" in action_type or "initialize_variable" in action_name.lower():
        for key in ("name", "variableName", "variable", "nombre"):
            value = inputs.get(key)
            if isinstance(value, str) and value.strip():
                found.append((f"{base_path}.inputs.{key}", value.strip()))

    return _dedupe_pairs(found)


def _extract_flow_parameter_names(flow_raw: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Primera versión heurística:
    busca parámetros en varios lugares comunes del JSON del flujo.
    """
    found: List[Tuple[str, str]] = []

    if not isinstance(flow_raw, dict):
        return found

    properties = flow_raw.get("properties")
    if not isinstance(properties, dict):
        properties = {}

    definition = flow_raw.get("definition")
    if not isinstance(definition, dict):
        definition = {}

    prop_definition = properties.get("definition")
    if not isinstance(prop_definition, dict):
        prop_definition = {}

    containers = [
        ("properties.definition.parameters", prop_definition.get("parameters")),
        ("definition.parameters", definition.get("parameters")),
        ("properties.parameters", properties.get("parameters")),
        ("parameters", flow_raw.get("parameters")),
    ]

    for base, container in containers:
        if isinstance(container, dict):
            for param_name in container.keys():
                if isinstance(param_name, str) and param_name.strip():
                    found.append((f"{base}.{param_name}", param_name.strip()))

    return _dedupe_pairs(found)


def _looks_sensitive_literal(path: str, value: str) -> bool:
    path_low = (path or "").lower()
    value = (value or "").strip()

    if not value or _is_dynamic_reference(value):
        return False

    # Cualquier correo literal entra como hardcode sensible
    if EMAIL_RE.search(value):
        return True

    sensitive_path_tokens = [
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "clientsecret", "client_secret", "privatekey", "private_key",
        "authorization", "accesskey", "access_key", "sas", "signature",
        "sig", "connectionstring", "connection_string", "correo", "email", "mail",
    ]

    if _classify_sensitivity(value):
        return True

    if any(token in path_low for token in sensitive_path_tokens):
        return True

    return False


def _looks_parametrizable_literal(path: str, value: str) -> bool:
    path_low = (path or "").lower()
    value = (value or "").strip()

    if not value:
        return False

    if _is_dynamic_reference(value):
        return False

    # Correos ya NO entran aquí
    if EMAIL_RE.search(value):
        return False

    # Si parece sensible, no es parametrizable
    if _classify_sensitivity(value):
        return False

    # Ignorar valores internos / schemas / referencias técnicas
    if _is_system_value(value):
        return False

    # Solo marcar si el path sí parece configurable
    path_has_hint = any(token in path_low for token in PARAMETRIZABLE_PATH_HINTS)
    if not path_has_hint:
        return False

    # URLs configurables
    if URL_RE.search(value):
        return True

    # Rutas Windows / Unix
    if WINDOWS_PATH_RE.search(value) or UNIX_PATH_RE.search(value):
        return True

    # Otros valores tipo path/archivo/host
    if ("/" in value or "\\" in value or "." in value) and len(value) > 3:
        return True

    return False


# =========================
# Rules (Flow level)
# =========================

def check_flow_naming(
    flow_name: str,
    source_file: str = "",
) -> List[Finding]:
    """
    Más flexible:
    - ya no exige UpperCamelCase de forma estricta
    - solo marca si hay acentos, caracteres raros o espacios dobles
    """
    findings: List[Finding] = []
    flow_name = (flow_name or "").strip()

    if not flow_name:
        return findings

    issues: List[str] = []

    if ACCENTS_RE.search(flow_name):
        issues.append("contiene acentos o ñ")

    if not FLOW_ALLOWED_RE.match(flow_name):
        issues.append("contiene caracteres especiales no permitidos")

    if "  " in flow_name:
        issues.append("contiene espacios dobles")

    if issues:
        findings.append(Finding(
            severity_level=1,
            rule_name="Nomenclatura de flujos y subflujos",
            flow_name=flow_name,
            action_name="",
            json_path="properties.displayName",
            reason="El nombre del flujo no cumple con una nomenclatura limpia: " + ", ".join(issues) + ".",
            evidence=f"Nombre del flujo: {flow_name}",
            impact="Reduce legibilidad, estandarización y mantenibilidad entre equipos.",
            fix="Renombrar el flujo usando un nombre limpio, sin acentos, sin caracteres especiales extraños y evitando espacios dobles."
        ))

    return findings


def check_parameter_prefixes(
    flow_name: str,
    flow_raw: Dict[str, Any],
) -> List[Finding]:
    """
    Regla: Prefijos de parámetros entre flujos
    Más flexible:
    - ignora parámetros del sistema
    - solo revisa nombres custom
    """
    findings: List[Finding] = []

    for path, param_name in _extract_flow_parameter_names(flow_raw):
        if not _is_custom_parameter_name(param_name):
            continue

        if not PARAM_NAME_RE.match(param_name):
            findings.append(Finding(
                severity_level=1,
                rule_name="Prefijos de parámetros entre flujos",
                flow_name=flow_name,
                action_name="",
                json_path=path,
                reason="El parámetro no sigue la convención esperada in_/out_/io_ + tipo de dato + nombre.",
                evidence=f"Parámetro: {param_name}",
                impact="Disminuye claridad del contrato entre flujos y complica mantenimiento o reuso.",
                fix="Renombrar el parámetro con prefijo in_, out_ o io_, seguido del tipo (Int/Str/Bln/Obj/Arr/Flt) y un nombre descriptivo."
            ))

    return findings


def check_writing_recommendations_flow(
    flow_name: str,
    flow_raw: Dict[str, Any],
) -> List[Finding]:
    """
    Regla: Recomendaciones de escritura
    Más flexible:
    - revisa parámetros custom del flujo
    - solo marca acentos/ñ o caracteres realmente problemáticos
    """
    findings: List[Finding] = []

    for path, param_name in _extract_flow_parameter_names(flow_raw):
        if not _is_custom_parameter_name(param_name):
            continue

        issues = _has_writing_issues(param_name)
        if issues:
            findings.append(Finding(
                severity_level=1,
                rule_name="Recomendaciones de escritura",
                flow_name=flow_name,
                action_name="",
                json_path=path,
                reason="El nombre del parámetro " + ", ".join(issues) + ".",
                evidence=f"Parámetro: {param_name}",
                impact="Genera inconsistencias de nomenclatura y dificulta la lectura del flujo.",
                fix="Renombrar el parámetro usando ASCII, sin acentos ni caracteres especiales problemáticos."
            ))

    return findings


def run_flow_rules(
    flow_name: str,
    flow_raw: Dict[str, Any],
    source_file: str = "",
) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_flow_naming(flow_name, source_file)
    findings += check_parameter_prefixes(flow_name, flow_raw)
    findings += check_writing_recommendations_flow(flow_name, flow_raw)
    return findings


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

    for path, s in _walk_values(action_raw.get("inputs", {}), f"{base_path}.inputs"):
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
    - Nivel 1 si contiene acentos/ñ
    - Nivel 2 si el nombre es default real
    """
    findings: List[Finding] = []

    if NAMING_ALLOWLIST_RE.match(action_name):
        return findings

    # Si tiene "_-_" o "-" lo consideramos "personalizado"
    if "_-_" in action_name or "-" in action_name:
        if ACCENTS_RE.search(action_name):
            findings.append(Finding(
                severity_level=1,
                rule_name="Naming de actividades",
                flow_name=flow_name,
                action_name=action_name,
                json_path=base_path,
                reason="El nombre contiene acentos/ñ; se recomienda solo ASCII para consistencia.",
                evidence=f"Nombre: {action_name}",
                impact="Inconsistencia de estandarización y potenciales diferencias entre equipos o entornos.",
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
            impact="Dificulta trazabilidad y mantenimiento porque no se entiende el propósito de la acción sin abrirla.",
            fix="Renombrar la acción con propósito claro (verbo + objeto), sin numeración."
        ))

    if ACCENTS_RE.search(action_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Naming de actividades",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason="El nombre contiene acentos/ñ; se recomienda solo ASCII para consistencia.",
            evidence=f"Nombre: {action_name}",
            impact="Inconsistencia de estandarización y potenciales diferencias entre equipos o entornos.",
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
    Cloud:
    Bln, Int, Flt, Str, Obj, Arr + UpperCamelCase
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
                fix="Renombrar la variable usando prefijo de tipo (Bln/Int/Flt/Str/Obj/Arr) y nombre descriptivo en UpperCamelCase."
            ))

    return findings


def check_writing_recommendations_action(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    """
    Regla: Recomendaciones de escritura
    Más flexible:
    - revisa variables inicializadas
    - solo marca acentos/ñ o caracteres realmente problemáticos
    """
    findings: List[Finding] = []

    for path, var_name in _extract_initialized_variable_names(action_name, action_raw, base_path):
        issues = _has_writing_issues(var_name)
        if issues:
            findings.append(Finding(
                severity_level=1,
                rule_name="Recomendaciones de escritura",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason="El nombre de la variable " + ", ".join(issues) + ".",
                evidence=f"Variable: {var_name}",
                impact="Genera inconsistencias de nomenclatura y dificulta la lectura o mantenimiento del flujo.",
                fix="Renombrar la variable usando ASCII, sin acentos ni caracteres especiales problemáticos."
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
    findings += check_writing_recommendations_action(flow_name, action_name, action_raw, base_path)
    return findings