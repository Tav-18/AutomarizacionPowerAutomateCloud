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
    r"^(Compose|Compose_\d+|"
    r"Initialize_variable|Initialize_variable_\d+|"
    r"Set_variable|Set_variable_\d+|"
    r"Condition|Condition_\d+|"
    r"Apply_to_each|Apply_to_each_\d+|"
    r"Scope|Scope_\d+|"
    r"Switch|Switch_\d+|"
    r"Delay|Delay_\d+|"
    r"Wait|Wait_\d+)$",
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

CURP_RE = re.compile(r"^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$", re.IGNORECASE)
RFC_RE = re.compile(r"^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$", re.IGNORECASE)
PHONE_RE = re.compile(r"^\+?\d{10,15}$")
GUID_RE = re.compile(
    r"^[{(]?[0-9a-fA-F]{8}[-]?[0-9a-fA-F]{4}[-]?[0-9a-fA-F]{4}[-]?[0-9a-fA-F]{4}[-]?[0-9a-fA-F]{12}[)}]?$"
)

RUNAFTER_CONTROL_TYPES = {
    "if",
    "switch",
    "scope",
    "foreach",
    "until",
}

RUNAFTER_RELEVANT_ACTION_TYPES = {
    "http",
    "workflow",
    "response",
    "parsejson",
}

RUNAFTER_RELEVANT_OPERATION_IDS = {
    "getfileitems",
    "getitem",
    "getitems",
    "getrow",
    "getrows",
    "getfilemetadata",
    "getfilemetadatausingpath",
}

RUNAFTER_EXCLUDED_OPERATION_IDS = {
    "createfile",
    "updatefile",
    "createfileitem",
}

PII_FIELD_HINTS = {
    "correo_electronico", "email", "mail", "correo",
    "curp", "rfc",
    "numero_de_seguridad_social", "nss", "imss",
    "telefono", "celular", "phone", "mobile",
    "fecha_nacimiento", "birthdate", "dateofbirth",
}

SENSITIVE_FIELD_HINTS = {
    "password", "passwd", "pwd",
    "secret", "token",
    "api_key", "apikey",
    "clientsecret", "client_secret",
    "privatekey", "private_key",
    "authorization",
    "accesskey", "access_key",
    "connectionstring", "connection_string",
    "recipient", "recipients",
    "to", "cc", "bcc",
}

PARAMETRIZABLE_HINTS = (
    "url", "uri", "endpoint",
    "path", "route",
    "folder", "directory",
    "file", "filename",
    "template",
    "host", "hostname",
    "baseurl", "base_url",
    "siteaddress", "server",
    "dataset", "table",
    "source", "drive",
    "blob", "container",
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
    severity_level: int
    rule_name: str
    flow_name: str
    action_name: str
    json_path: str
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


def _dedupe_pairs(items: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    seen = set()
    out: List[Tuple[str, str]] = []

    for path, value in items:
        key = (path, value)
        if key not in seen:
            seen.add(key)
            out.append((path, value))

    return out


def _leaf_path_name(path: str) -> str:
    if not path:
        return ""
    parts = path.split(".")
    leaf = parts[-1] if parts else ""
    leaf = re.sub(r"\[\d+\]$", "", leaf)
    return leaf.lower().strip()


def _parent_path_name(path: str) -> str:
    if not path:
        return ""
    parts = path.split(".")
    if len(parts) < 2:
        return ""
    parent = parts[-2]
    parent = re.sub(r"\[\d+\]$", "", parent)
    return parent.lower().strip()


def _classify_sensitivity(text: str) -> bool:
    if not text:
        return False

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


def _extract_initialized_variable_names(
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []

    raw_inputs = action_raw.get("inputs")
    if not isinstance(raw_inputs, dict):
        return found

    inputs = raw_inputs
    action_type = str(action_raw.get("type", "") or "").lower()
    action_name_low = (action_name or "").lower()

    variables = inputs.get("variables")
    if isinstance(variables, list):
        for i, item in enumerate(variables):
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if name:
                    found.append((f"{base_path}.inputs.variables[{i}].name", name))

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


def _looks_sensitive_literal(path: str, value: str) -> bool:
    value = (value or "").strip()
    path_low = (path or "").lower()

    if not value:
        return False

    if _is_dynamic_reference(value) or _is_system_value(value):
        return False

    if _is_schema_path(path):
        return False

    if _is_connector_plumbing_path(path):
        return False

    leaf = _leaf_path_name(path)
    parent = _parent_path_name(path)

    # excluir textos operativos muy comunes
    non_sensitive_literals = {
        "ok",
        "na",
        "n/a",
        "exception",
        "true",
        "false",
        "null",
        "string",
        "object",
        "array",
        "integer",
        "number",
        "boolean",
        "bearer_token",
        "client_credential",
        "default",
        "prod",
        "post",
        "get",
    }

    if value.lower() in non_sensitive_literals:
        return False

    # excluir paths de mensajes/respuestas
    non_sensitive_path_tokens = (
        ".message",
        ".status",
        ".reentry",
        ".authenticationmethod",
        ".granttype",
    )
    if any(token in path_low for token in non_sensitive_path_tokens):
        return False

    if leaf == "name":
        return False

    if EMAIL_RE.search(value):
        return True

    if leaf in SENSITIVE_FIELD_HINTS or parent in SENSITIVE_FIELD_HINTS:
        return True

    if leaf in PII_FIELD_HINTS or parent in PII_FIELD_HINTS:
        if value.lower() in {"string", "object", "array", "integer", "number", "boolean", "null"}:
            return False
        return True

    if CURP_RE.match(value):
        return True

    if RFC_RE.match(value):
        return True

    if PHONE_RE.match(re.sub(r"[^\d+]", "", value)):
        return True

    if _classify_sensitivity(value):
        return True

    return False

def _is_schema_path(path: str) -> bool:
    path_low = (path or "").lower()

    schema_tokens = (
        ".schema.",
        ".properties.",
        ".items.",
        ".required[",
        ".type",
        ".title",
        ".description",
        "x-ms-",
    )

    return any(token in path_low for token in schema_tokens)


def _is_connector_plumbing_path(path: str) -> bool:
    path_low = (path or "").lower()

    noisy_tokens = (
        ".inputs.parameters.dataset",
        ".inputs.parameters.source",
        ".inputs.parameters.folderpath",
        ".inputs.parameters.id",
        ".inputs.parameters.name",
        ".inputs.host.apiid",
        ".inputs.host.connectionname",
        ".inputs.host.operationid",
        ".runtimeconfiguration.",
    )

    return any(token in path_low for token in noisy_tokens)


def _is_child_flow_path(path: str) -> bool:
    path_low = (path or "").lower()

    child_flow_tokens = (
        ".inputs.host.workflowreferencename",
        ".host.workflowreferencename",
        ".workflowreferencename",
    )

    return any(token in path_low for token in child_flow_tokens)

def _looks_parametrizable_literal(path: str, value: str) -> bool:
    value = (value or "").strip()
    path_low = (path or "").lower()
    leaf = _leaf_path_name(path)

    if not value:
        return False

    if _is_schema_path(path):
        return False

    if _is_connector_plumbing_path(path):
        return False

    if _is_child_flow_path(path):
        return False

    if _is_dynamic_reference(value) or _is_system_value(value):
        return False

    if EMAIL_RE.search(value):
        return False

    if _classify_sensitivity(value):
        return False

    if CURP_RE.match(value) or RFC_RE.match(value):
        return False

    if leaf in PII_FIELD_HINTS:
        return False

    # excluir nombres/refs de workflows
    workflow_tokens = (
        "workflowreferencename",
        "childflow",
        "run a child flow",
    )
    if any(token in path_low for token in workflow_tokens):
        return False

    field_looks_configurable = any(token in leaf for token in PARAMETRIZABLE_HINTS)

    if not field_looks_configurable:
        field_looks_configurable = any(f".{token}" in path_low for token in PARAMETRIZABLE_HINTS)

    # permitir explícitamente rutas de archivo/tabla/drive aunque no entren por hints
    if not field_looks_configurable:
        explicit_param_tokens = (
            ".inputs.parameters.file",
            ".inputs.parameters.table",
            ".inputs.parameters.drive",
        )
        field_looks_configurable = any(token in path_low for token in explicit_param_tokens)

    if not field_looks_configurable:
        return False

    if URL_RE.search(value):
        return True

    if WINDOWS_PATH_RE.search(value) or UNIX_PATH_RE.search(value):
        return True

    if re.search(r"\.(xlsx|xls|docx|doc|csv|txt|json|pdf)$", value, re.IGNORECASE):
        return True

    low_value = value.lower()
    if "sharepoint.com" in low_value or "blob.core.windows.net" in low_value:
        return True

    if GUID_RE.match(value):
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
    Regla consolidada por actividad:
    - 1 finding de Hardcode por actividad
    - 1 finding de Parametrizable por actividad

    Esto evita generar una incidencia por cada campo detectado dentro
    de la misma acción.
    """
    findings: List[Finding] = []

    raw_inputs = action_raw.get("inputs")
    if isinstance(raw_inputs, (dict, list, str)):
        walk_source = raw_inputs
    else:
        walk_source = {}

    hardcode_hits: List[Tuple[str, str]] = []
    parametrizable_hits: List[Tuple[str, str]] = []

    for path, s in _walk_values(walk_source, f"{base_path}.inputs"):
        value = (s or "").strip()
        if not value:
            continue

        if _looks_sensitive_literal(path, value):
            hardcode_hits.append((path, value))
            continue

        if _looks_parametrizable_literal(path, value):
            parametrizable_hits.append((path, value))

    # Consolidar Hardcode a una sola incidencia por actividad
    if hardcode_hits:
        unique_paths = []
        seen_paths = set()

        for path, _ in hardcode_hits:
            if path not in seen_paths:
                seen_paths.add(path)
                unique_paths.append(path)

        sample_paths = unique_paths[:5]
        total_hits = len(hardcode_hits)

        findings.append(Finding(
            severity_level=3,
            rule_name="Hardcode",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason=(
                f"Se detectaron {total_hits} valores sensibles hardcodeados "
                f"dentro de la misma actividad."
            ),
            evidence=" | ".join(sample_paths),
            impact=(
                "Riesgo de exposición de correos, credenciales, tokens o información "
                "sensible; además acopla el flujo a una configuración insegura."
            ),
            fix=(
                "Mover estos valores a un mecanismo seguro "
                "(por ejemplo Key Vault, connection reference o variable de entorno protegida) "
                "y resolverlos dinámicamente."
            )
        ))

    # Consolidar Parametrizable a una sola incidencia por actividad
    if parametrizable_hits:
        unique_paths = []
        seen_paths = set()

        for path, _ in parametrizable_hits:
            if path not in seen_paths:
                seen_paths.add(path)
                unique_paths.append(path)

        sample_paths = unique_paths[:5]
        total_hits = len(parametrizable_hits)

        findings.append(Finding(
            severity_level=2,
            rule_name="Parametrizable",
            flow_name=flow_name,
            action_name=action_name,
            json_path=base_path,
            reason=(
                f"Se detectaron {total_hits} valores fijos no sensibles que "
                f"deberían parametrizarse dentro de la misma actividad."
            ),
            evidence=" | ".join(sample_paths),
            impact="Complica promoción entre ambientes, mantenimiento y cambios futuros.",
            fix=(
                "Mover estos valores a un mecanismo parametrizable "
                "(variables de entorno, parámetros, connection references o configuración central)."
            )
        ))

    return findings

def _get_operation_id(action_raw: Dict[str, Any]) -> str:
    inputs = action_raw.get("inputs")
    if not isinstance(inputs, dict):
        return ""

    host = inputs.get("host")
    if not isinstance(host, dict):
        return ""

    return str(host.get("operationId", "") or "").strip().lower()


def _is_nested_control_path(base_path: str) -> bool:
    """
    Detecta si la acción vive dentro de una rama/estructura,
    pero NO debe usarse para excluir todas las nested actions operativas.
    """
    path = (base_path or "").lower()

    return any(token in path for token in (
        ".else.actions.",
        ".cases.",
        ".defaultcase.actions.",
        ".branches[",
    ))

def _should_check_runafter(action_name: str, action_raw: Dict[str, Any], base_path: str) -> bool:
    action_type = str(action_raw.get("type", "") or "").strip().lower()
    action_name_low = (action_name or "").strip().lower()
    operation_id = _get_operation_id(action_raw)

    if action_type in RUNAFTER_CONTROL_TYPES:
        return False

    control_name_hints = (
        "condition",
        "if",
        "switch",
        "scope",
        "apply_to_each",
        "foreach",
        "until",
    )

    if action_name_low in control_name_hints:
        return False

    if any(action_name_low.startswith(hint) for hint in control_name_hints):
        return False

    if operation_id in RUNAFTER_EXCLUDED_OPERATION_IDS:
        return False

    if action_type in RUNAFTER_RELEVANT_ACTION_TYPES:
        return True

    if operation_id in RUNAFTER_RELEVANT_OPERATION_IDS:
        return True

    return False

def _is_integration_action(action_raw: Dict[str, Any]) -> bool:
    """
    Detecta acciones que sí vale la pena revisar con RunAfter
    porque suelen implicar integración externa, conectores o llamadas.
    """
    action_type = str(action_raw.get("type", "") or "").strip().lower()

    if action_type in {"http", "workflow", "openapiconnection", "apiconnection"}:
        return True

    inputs = action_raw.get("inputs")
    if not isinstance(inputs, dict):
        return False

    host = inputs.get("host")
    if isinstance(host, dict):
        api_id = str(host.get("apiId", "") or "").strip()
        connection_name = str(host.get("connectionName", "") or "").strip()
        operation_id = str(host.get("operationId", "") or "").strip()

        if api_id or connection_name or operation_id:
            return True

    return False


def check_missing_runafter(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    if not _should_check_runafter(action_name, action_raw, base_path):
        return []

    run_after = action_raw.get("runAfter")

    if run_after is None:
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
    findings: List[Finding] = []

    action_type = str(action_raw.get("type", "") or "").lower()
    action_name_low = (action_name or "").lower()

    is_delay_action = (
        DELAY_NAME_RE.search(action_name_low) is not None
        or action_type in ("delay", "wait")
    )

    if not is_delay_action:
        return findings

    raw_inputs = action_raw.get("inputs")
    inputs = raw_inputs if isinstance(raw_inputs, dict) else {}

    interval = inputs.get("interval")
    if isinstance(interval, dict):
        count = interval.get("count")
        unit = interval.get("unit")

        if isinstance(count, (int, float)) or (isinstance(count, str) and count.strip()):
            findings.append(Finding(
                severity_level=2,
                rule_name="Retrasos",
                flow_name=flow_name,
                action_name=action_name,
                json_path=f"{base_path}.inputs.interval",
                reason="Se detectó una acción Delay/Wait con intervalo literal configurado.",
                evidence=f"count={count}, unit={unit}",
                impact="Aumenta tiempos de ejecución y puede volver frágil el flujo si cambian tiempos o latencias del entorno.",
                fix="Evitar delays innecesarios; si se requiere, justificar y parametrizar el intervalo o usar una condición de espera más robusta."
            ))
            return findings

    for path, s in _walk_values(inputs, f"{base_path}.inputs"):
        if re.search(r"\b\d+\b", s) or re.search(r"PT\d", s, re.IGNORECASE):
            findings.append(Finding(
                severity_level=2,
                rule_name="Retrasos",
                flow_name=flow_name,
                action_name=action_name,
                json_path=path,
                reason="Se detectó Delay/Wait con valor literal; puede degradar rendimiento y volver frágil el flujo.",
                evidence=s[:240],
                impact="Aumenta tiempos de ejecución y puede fallar si cambian tiempos o latencias del entorno.",
                fix="Evitar delays innecesarios; si se requiere, justificar y parametrizar o usar una condición de espera más robusta."
            ))
            return findings

    return findings


def check_action_naming_cloud(
    flow_name: str,
    action_name: str,
    base_path: str
) -> List[Finding]:
    findings: List[Finding] = []

    if NAMING_ALLOWLIST_RE.match(action_name):
        return findings

    if "_-_" in action_name or "-" in action_name:
        if re.search(r"[áéíóúñÁÉÍÓÚÑ]", action_name):
            findings.append(Finding(
                severity_level=1,
                rule_name="Nomenclatura de actividades",
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
            rule_name="Nomenclatura de actividades",
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
            rule_name="Nomenclatura de actividades",
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