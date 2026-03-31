import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
import unicodedata


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

CURP_RE = re.compile(r"^"
    r"[A-Z][AEIOUX][A-Z]{2}"
    r"\d{2}(0[1-9]|1[0-2])"
    r"(0[1-9]|[12]\d|3[01])"
    r"[HM]"
    r"(AS|BC|BS|CC|CL|CM|CS|CH|DF|DG|GT|GR|HG|JC|MC|MN|MS|"
    r"NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)"
    r"[B-DF-HJ-NP-TV-Z]{3}"
    r"[A-Z0-9]"
    r"\d"
    r"$",
    re.IGNORECASE
)

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

FLOW_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9_]*$")

IO_PREFIX_RE = re.compile(
    r"^(in_|out_|io_)(Bln|Int|Flt|Str|Obj|Arr)[A-Z][A-Za-z0-9]*$"
)

COMMENT_RELEVANT_TYPES = {
    "scope",
    "if",
    "switch",
    "foreach",
    "http",
    "openapiconnection",
    "workflow",
    "response",
    "parsejson",
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
    severity_level: int
    rule_name: str
    flow_name: str
    action_name: str
    json_path: str
    reason: str
    evidence: str
    impact: str
    fix: str
    repeat_count: int = 1


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

GENERIC_SCHEMA_VALUES = {
    "string", "object", "array", "integer", "number", "boolean", "null"
}

PII_FIELD_ALIASES = {
    "email": {
        "correo", "correoelectronico", "email", "mail"
    },
    "curp": {
        "curp"
    },
    "rfc": {
        "rfc"
    },
    "phone": {
        "telefono", "celular", "phone", "mobile"
    },
    "nss": {
        "numerodeseguridadsocial", "nss", "imss"
    },
    "birthdate": {
        "fechanacimiento", "fecha_nacimiento", "birthdate", "dateofbirth"
    },
}

SENSITIVE_FIELD_HINTS_N = {
    "password", "passwd", "pwd",
    "secret", "token",
    "apikey", "clientsecret",
    "privatekey", "authorization",
    "accesskey", "connectionstring",
    "recipient", "recipients",
    "to", "cc", "bcc",
}

PARAM_FIELD_ALIASES = {
    "url", "uri", "endpoint",
    "path", "route", "ruta",
    "folder", "directory", "carpeta", "directorio",
    "file", "filename", "archivo", "nombrearchivo",
    "template", "plantilla",
    "host", "hostname", "servidor",
    "baseurl", "siteaddress", "sitio",
    "dataset", "table", "tabla",
    "source", "drive",
    "blob", "container", "contenedor",
}

def _strip_accents(text: str) -> str:
    text = text or ""
    return "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )

def _normalize_compare_key(text: str) -> str:
    s = _strip_accents(text).lower().strip()
    return re.sub(r"[^a-z0-9]", "", s)

def _normalize_field_name(name: str) -> str:
    """
    Normaliza nombres de campos para detectar variantes como:
    cur_p, cur-p, CURP_1, correo-electronico, telefono2, etc.
    """
    s = _strip_accents(name).lower().strip()

    # quita sufijos numéricos al final: curp2, curp_2, telefono-1
    s = re.sub(r"[\W_]*\d+$", "", s)

    # deja solo letras y números
    s = re.sub(r"[^a-z0-9]", "", s)
    return s

def _normalize_default_action_name(name: str) -> str:
    """
    Convierte:
    Apply to each -> Apply_to_each
    Delay-2       -> Delay_2
    """
    s = _strip_accents(name or "").strip()
    s = re.sub(r"[\s\-]+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s

def _normalized_leaf_and_parent(path: str) -> tuple[str, str]:
    leaf = _normalize_field_name(_leaf_path_name(path))
    parent = _normalize_field_name(_parent_path_name(path))
    return leaf, parent

def _pii_kind_from_path(path: str, action_raw: Dict[str, Any] | None = None) -> str | None:
    candidates = _candidate_field_names(path, action_raw)

    for kind, aliases in PII_FIELD_ALIASES.items():
        if candidates & aliases:
            return kind

    return None

def _has_sensitive_hint(path: str, action_raw: Dict[str, Any] | None = None) -> bool:
    candidates = _candidate_field_names(path, action_raw)
    return bool(candidates & SENSITIVE_FIELD_HINTS_N)

def _has_param_hint(path: str, action_raw: Dict[str, Any] | None = None) -> bool:
    candidates = _candidate_field_names(path, action_raw)
    return bool(candidates & PARAM_FIELD_ALIASES)

def _matches_pii_by_field_hint(path: str, value: str, action_raw: Dict[str, Any] | None = None) -> bool:
    value = (value or "").strip()
    if not value:
        return False

    if value.lower() in GENERIC_SCHEMA_VALUES:
        return False

    kind = _pii_kind_from_path(path, action_raw)
    if not kind:
        return False

    if kind == "email":
        return EMAIL_RE.fullmatch(value) is not None

    if kind == "curp":
        return CURP_RE.fullmatch(value) is not None

    if kind == "rfc":
        return RFC_RE.fullmatch(value) is not None

    if kind == "phone":
        normalized = re.sub(r"[^\d+]", "", value)
        return PHONE_RE.fullmatch(normalized) is not None

    if kind == "nss":
        normalized = re.sub(r"\D", "", value)
        return len(normalized) in {10, 11}

    if kind == "birthdate":
        return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value))

    return False

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


def _looks_sensitive_literal(path: str, value: str, action_raw: Dict[str, Any] | None = None) -> bool:
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

    leaf, _ = _normalized_leaf_and_parent(path)

    non_sensitive_literals = {
        "ok", "na", "n/a", "exception", "true", "false", "null",
        "string", "object", "array", "integer", "number", "boolean",
        "bearer_token", "client_credential", "default", "prod", "post", "get",
    }

    if value.lower() in non_sensitive_literals:
        return False

    non_sensitive_path_tokens = (
        ".message", ".status", ".reentry", ".authenticationmethod", ".granttype",
    )
    if any(token in path_low for token in non_sensitive_path_tokens):
        return False

    if leaf == "name":
        return False

    if EMAIL_RE.fullmatch(value):
        return True

    if _pii_kind_from_path(path, action_raw):
        return _matches_pii_by_field_hint(path, value, action_raw)

    if _has_sensitive_hint(path, action_raw):
        return True

    if CURP_RE.fullmatch(value):
        return True

    if RFC_RE.fullmatch(value):
        return True

    normalized_phone = re.sub(r"[^\d+]", "", value)
    if PHONE_RE.fullmatch(normalized_phone):
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

def _looks_parametrizable_literal(path: str, value: str, action_raw: Dict[str, Any] | None = None) -> bool:
    value = (value or "").strip()
    path_low = (path or "").lower()

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

    if CURP_RE.fullmatch(value) or RFC_RE.fullmatch(value):
        return False

    if _pii_kind_from_path(path, action_raw):
        return False

    if _has_sensitive_hint(path, action_raw):
        return False

    field_looks_configurable = _has_param_hint(path, action_raw)

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

    if GUID_RE.fullmatch(value):
        return True

    if ("/" in value or "\\" in value or "." in value) and len(value) > 3:
        return True

    return False


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

        if _looks_sensitive_literal(path, value, action_raw):
            hardcode_hits.append((path, value))
            continue

        if _looks_parametrizable_literal(path, value, action_raw):
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
            reason= "Se detectaron valores sensibles hardcodeados dentro de la misma actividad",
            evidence=" | ".join(sample_paths),
            impact=(
                "Riesgo de exposición de correos, credenciales, tokens o información "
                "sensible; además acopla el flujo a una configuración insegura."
            ),
            fix=(
                "Mover estos valores a un mecanismo seguro "
                "(por ejemplo Key Vault, connection reference o variable de entorno protegida) "
                "y resolverlos dinámicamente."
            ),
            repeat_count=total_hits,
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
            reason= "Se detectaron valores fijos no sensibles que deberían parametrizarse dentro de la misma actividad.",
            evidence=" | ".join(sample_paths),
            impact="Complica promoción entre ambientes, mantenimiento y cambios futuros.",
            fix=(
                "Mover estos valores a un mecanismo parametrizable "
                "(variables de entorno, parámetros, connection references o configuración central)."
            ),
            repeat_count=total_hits,
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
    action_type = _normalize_compare_key(str(action_raw.get("type", "") or ""))
    action_name_key = _normalize_compare_key(action_name or "")
    operation_id = _normalize_compare_key(_get_operation_id(action_raw))

    runafter_control_types = {"if", "switch", "scope", "foreach", "until"}
    control_name_hints = {"condition", "if", "switch", "scope", "applytoeach", "foreach", "until"}
    runafter_relevant_types = {"http", "workflow"}
    runafter_relevant_ops = {
        "getfileitems",
        "getitem",
        "getitems",
        "getrow",
        "getrows",
        "getfilemetadata",
        "getfilemetadatausingpath",
    }
    runafter_excluded_ops = {
        "createfile",
        "updatefile",
        "createfileitem",
    }

    if action_type in runafter_control_types:
        return False

    if action_name_key in control_name_hints:
        return False

    if any(action_name_key.startswith(hint) for hint in control_name_hints):
        return False

    if operation_id in runafter_excluded_ops:
        return False

    if action_type in runafter_relevant_types:
        return True

    if operation_id in runafter_relevant_ops:
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

    action_type = _normalize_compare_key(str(action_raw.get("type", "") or ""))
    action_name_key = _normalize_compare_key(action_name or "")

    is_delay_action = (
        action_type in {"delay", "wait"}
        or action_name_key in {"delay", "wait"}
        or action_name_key.startswith("delay")
        or action_name_key.startswith("wait")
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
                rule_name="Retrasos (Delay y Wait)",
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
                rule_name="Retrasos (Delay y Wait)",
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

    allowlist_key = _normalize_compare_key(action_name)
    if allowlist_key in {"whenahttprequestisreceived", "recurrence"}:
        return findings

    default_name_key = _normalize_default_action_name(action_name)

    if DEFAULT_ACTION_NAME_RE.match(default_name_key):
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

def _extract_context_names_for_value_path(path: str, action_raw: Dict[str, Any]) -> set[str]:
    names: set[str] = set()

    raw_inputs = action_raw.get("inputs")
    if not isinstance(raw_inputs, dict):
        return names

    inputs = raw_inputs

    # Caso SetVariable / similares: inputs.value + inputs.name
    if path.endswith(".inputs.value"):
        for key in ("name", "variableName", "variable", "nombre"):
            v = inputs.get(key)
            if isinstance(v, str) and v.strip():
                names.add(_normalize_field_name(v))

    # Caso InitializeVariable: inputs.variables[i].value -> usar inputs.variables[i].name
    m = re.search(r"\.inputs\.variables\[(\d+)\]\.value$", path)
    if m:
        idx = int(m.group(1))
        variables = inputs.get("variables")
        if isinstance(variables, list) and 0 <= idx < len(variables):
            item = variables[idx]
            if isinstance(item, dict):
                v = item.get("name")
                if isinstance(v, str) and v.strip():
                    names.add(_normalize_field_name(v))

    return names


def _candidate_field_names(path: str, action_raw: Dict[str, Any] | None = None) -> set[str]:
    leaf, parent = _normalized_leaf_and_parent(path)
    candidates = {leaf, parent}

    if action_raw is not None:
        candidates |= _extract_context_names_for_value_path(path, action_raw)

    return {x for x in candidates if x}


def _collect_relevant_actions_recursive(actions_dict: Dict[str, Any], out: List[Tuple[str, Dict[str, Any], str]], base_path: str = "actions") -> None:
    if not isinstance(actions_dict, dict):
        return

    relevant_types = {
        "scope",
        "if",
        "switch",
        "foreach",
        "http",
        "openapiconnection",
        "workflow",
        "response",
        "parsejson",
    }

    for action_name, action_body in actions_dict.items():
        if not isinstance(action_body, dict):
            continue

        current_path = f"{base_path}.{action_name}"
        action_type = _normalize_compare_key(str(action_body.get("type", "") or ""))

        if action_type in relevant_types:
            out.append((action_name, action_body, current_path))

        nested_actions = action_body.get("actions")
        if isinstance(nested_actions, dict) and nested_actions:
            _collect_relevant_actions_recursive(nested_actions, out, f"{current_path}.actions")

        else_block = action_body.get("else")
        if isinstance(else_block, dict):
            else_actions = else_block.get("actions")
            if isinstance(else_actions, dict) and else_actions:
                _collect_relevant_actions_recursive(else_actions, out, f"{current_path}.else.actions")

        cases = action_body.get("cases")
        if isinstance(cases, dict):
            for case_name, case_body in cases.items():
                if not isinstance(case_body, dict):
                    continue
                case_actions = case_body.get("actions")
                if isinstance(case_actions, dict) and case_actions:
                    _collect_relevant_actions_recursive(case_actions, out, f"{current_path}.cases.{case_name}.actions")

        default_case = action_body.get("defaultCase")
        if isinstance(default_case, dict):
            default_actions = default_case.get("actions")
            if isinstance(default_actions, dict) and default_actions:
                _collect_relevant_actions_recursive(default_actions, out, f"{current_path}.defaultCase.actions")


def _has_meaningful_description(action_raw: Dict[str, Any]) -> bool:
    desc = str(action_raw.get("description", "") or "").strip()
    if not desc:
        return False

    # evita contar placeholders vacíos o comentarios mínimos
    noisy = {"n", "na", "n/a", ".", "-", "_"}
    if desc.lower() in noisy:
        return False

    return len(desc) >= 8


def _extract_trigger_and_response_names(flow_raw: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """
    Devuelve tuplas:
    (kind, name_found, path)
    kind = trigger_input | response_output
    """
    found: List[Tuple[str, str, str]] = []

    definition = (
        flow_raw.get("properties", {}).get("definition")
        or flow_raw.get("definition")
        or {}
    )

    # Trigger inputs
    triggers = definition.get("triggers") or {}
    for trigger_name, trigger_body in triggers.items():
        if not isinstance(trigger_body, dict):
            continue

        schema = (trigger_body.get("inputs") or {}).get("schema") or {}
        props = schema.get("properties") or {}

        if isinstance(props, dict):
            for prop_name, prop_body in props.items():
                if not isinstance(prop_body, dict):
                    continue

                candidate = (
                    str(prop_body.get("title", "") or "").strip()
                    or str(prop_name or "").strip()
                )
                if candidate:
                    found.append((
                        "trigger_input",
                        candidate,
                        f"triggers.{trigger_name}.inputs.schema.properties.{prop_name}"
                    ))

    # Response outputs
    actions = definition.get("actions") or {}
    response_actions: List[Tuple[str, Dict[str, Any], str]] = []
    _collect_relevant_actions_recursive(actions, response_actions)

    for action_name, action_body, action_path in response_actions:
        action_type = _normalize_compare_key(str(action_body.get("type", "") or ""))
        if action_type != "response":
            continue

        schema = (action_body.get("inputs") or {}).get("schema") or {}
        props = schema.get("properties") or {}

        if isinstance(props, dict):
            for prop_name, prop_body in props.items():
                if not isinstance(prop_body, dict):
                    continue

                candidate = (
                    str(prop_body.get("title", "") or "").strip()
                    or str(prop_name or "").strip()
                )
                if candidate:
                    found.append((
                        "response_output",
                        candidate,
                        f"{action_path}.inputs.schema.properties.{prop_name}"
                    ))

    return found


def _flow_definition_actions(flow_raw: Dict[str, Any]) -> Dict[str, Any]:
    definition = (
        flow_raw.get("properties", {}).get("definition")
        or flow_raw.get("definition")
        or {}
    )
    return definition.get("actions") or {}

def check_if_condition_structure(
    flow_name: str,
    action_name: str,
    action_raw: Dict[str, Any],
    base_path: str
) -> List[Finding]:
    findings: List[Finding] = []

    action_type = _normalize_compare_key(str(action_raw.get("type", "") or ""))
    if action_type != "if":
        return findings

    then_actions = action_raw.get("actions")
    if not isinstance(then_actions, dict) or not then_actions:
        findings.append(Finding(
            severity_level=1,
            rule_name="Condición IF",
            flow_name=flow_name,
            action_name=action_name,
            json_path=f"{base_path}.actions",
            reason="La condición IF tiene la rama principal vacía o sin acciones útiles.",
            evidence="Rama Then sin acciones.",
            impact="Reduce legibilidad y puede ocultar una lógica mal estructurada o incompleta.",
            fix="Agregar la lógica principal en la rama Then o replantear la estructura de la condición."
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
    findings += check_if_condition_structure(flow_name, action_name, action_raw, base_path)
    return findings

def check_flow_parameter_prefixes(flow_name: str, flow_raw: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    for kind, candidate_name, path in _extract_trigger_and_response_names(flow_raw):
        normalized = candidate_name.strip()

        if kind == "trigger_input":
            if not normalized.startswith("in_"):
                findings.append(Finding(
                    severity_level=1,
                    rule_name="Prefijos variables / parámetros",
                    flow_name=flow_name,
                    action_name="(flow)",
                    json_path=path,
                    reason="El parámetro de entrada no utiliza el prefijo esperado 'in_'.",
                    evidence=f"Parámetro detectado: {normalized}",
                    impact="Dificulta entender la dirección del dato entre flujos relacionados.",
                    fix="Renombrar el parámetro usando el prefijo in_ seguido del tipo de dato y un nombre descriptivo."
                ))
                continue

            if not IO_PREFIX_RE.match(normalized):
                findings.append(Finding(
                    severity_level=1,
                    rule_name="Prefijos variables / parámetros",
                    flow_name=flow_name,
                    action_name="(flow)",
                    json_path=path,
                    reason="El parámetro de entrada no respeta la convención completa de prefijo, tipo y nombre descriptivo.",
                    evidence=f"Parámetro detectado: {normalized}",
                    impact="Reduce consistencia y dificulta entender el contrato entre flujos.",
                    fix="Usar el formato in_ + tipo (Bln/Int/Flt/Str/Obj/Arr) + nombre descriptivo en UpperCamelCase."
                ))
                continue

        elif kind == "response_output":
            if not (normalized.startswith("out_") or normalized.startswith("io_")):
                findings.append(Finding(
                    severity_level=1,
                    rule_name="Prefijos variables / parámetros",
                    flow_name=flow_name,
                    action_name="(flow)",
                    json_path=path,
                    reason="El parámetro de salida no utiliza el prefijo esperado 'out_' o 'io_'.",
                    evidence=f"Parámetro detectado: {normalized}",
                    impact="Complica el entendimiento de entradas y salidas entre flujos.",
                    fix="Renombrar el parámetro usando out_ o io_ según corresponda, seguido del tipo y un nombre descriptivo."
                ))
                continue

            if not IO_PREFIX_RE.match(normalized):
                findings.append(Finding(
                    severity_level=1,
                    rule_name="Prefijos variables / parámetros",
                    flow_name=flow_name,
                    action_name="(flow)",
                    json_path=path,
                    reason="El parámetro de salida no respeta la convención completa de prefijo, tipo y nombre descriptivo.",
                    evidence=f"Parámetro detectado: {normalized}",
                    impact="Reduce consistencia y dificulta entender el contrato entre flujos.",
                    fix="Usar el formato out_/io_ + tipo (Bln/Int/Flt/Str/Obj/Arr) + nombre descriptivo en UpperCamelCase."
                ))
                continue

    return findings

def check_flow_comments(flow_name: str, flow_raw: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    actions = _flow_definition_actions(flow_raw)
    relevant_actions: List[Tuple[str, Dict[str, Any], str]] = []
    _collect_relevant_actions_recursive(actions, relevant_actions)

    if len(relevant_actions) < 3:
        return findings

    documented = 0
    undocumented_examples: List[str] = []

    for action_name, action_body, action_path in relevant_actions:
        if _has_meaningful_description(action_body):
            documented += 1
        elif len(undocumented_examples) < 5:
            undocumented_examples.append(action_name)

    coverage = documented / len(relevant_actions)

    if coverage < 0.33:
        findings.append(Finding(
            severity_level=1,
            rule_name="Comentarios descriptivos",
            flow_name=flow_name,
            action_name="(flow)",
            json_path="actions",
            reason=f"Solo {documented} de {len(relevant_actions)} acciones relevantes tienen descripción visible ({coverage:.0%}).",
            evidence="Acciones sin descripción: " + ", ".join(undocumented_examples) if undocumented_examples else "Cobertura de comentarios insuficiente.",
            impact="Dificulta entendimiento, mantenimiento y revisión del flujo.",
            fix="Agregar descripciones visibles en acciones y ámbitos clave hasta alcanzar al menos 33% de cobertura."
        ))

    return findings

def check_flow_naming(flow_name: str) -> List[Finding]:
    findings: List[Finding] = []

    base_name = str(flow_name or "").strip()

    if not base_name:
        return findings

    if re.search(r"[áéíóúñÁÉÍÓÚÑ]", base_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Nomenclatura de flujos",
            flow_name=flow_name,
            action_name="(flow)",
            json_path="flow_name",
            reason="El nombre del flujo contiene acentos o ñ.",
            evidence=f"Nombre del flujo: {base_name}",
            impact="Genera inconsistencia de nomenclatura dentro de la solución.",
            fix="Renombrar el flujo usando solo ASCII, sin acentos ni caracteres especiales."
        ))
        return findings

    if " " in base_name:
        findings.append(Finding(
            severity_level=1,
            rule_name="Nomenclatura de flujos",
            flow_name=flow_name,
            action_name="(flow)",
            json_path="flow_name",
            reason="El nombre del flujo contiene espacios.",
            evidence=f"Nombre del flujo: {base_name}",
            impact="Reduce uniformidad y dificulta mantener una convención consistente.",
            fix="Renombrar el flujo sin espacios y con una convención uniforme."
        ))
        return findings

    # marcar solo si tiene caracteres especiales realmente problemáticos
    if re.search(r"[^A-Za-z0-9_]", base_name):
        findings.append(Finding(
            severity_level=1,
            rule_name="Nomenclatura de flujos",
            flow_name=flow_name,
            action_name="(flow)",
            json_path="flow_name",
            reason="El nombre del flujo contiene caracteres especiales no recomendados.",
            evidence=f"Nombre del flujo: {base_name}",
            impact="Dificulta mantener una convención clara y uniforme dentro de la solución.",
            fix="Usar letras, números y guion bajo, evitando caracteres especiales innecesarios."
        ))

    return findings


def run_flow_level_rules(flow_name: str, flow_raw: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_flow_parameter_prefixes(flow_name, flow_raw)
    findings += check_flow_naming(flow_name)
    findings += check_flow_comments(flow_name, flow_raw)
    return findings