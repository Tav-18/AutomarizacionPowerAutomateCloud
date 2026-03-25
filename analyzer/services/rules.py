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
    if not path:
        return ""

    parts = path.split(".")
    if not parts:
        return ""

    leaf = parts[-1]
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

    if _is_system_value(value):
        return False

    leaf = _leaf_path_name(path)
    parent = _parent_path_name(path)

    # Si solo es el nombre de una variable/campo, no es hardcode sensible
    # Ejemplo: inputs.variables[0].name = "Password"
    if leaf == "name":
        return False

    # 1) Correos literales siempre entran como sensibles
    if EMAIL_RE.search(value):
        return True

    # 2) Campos técnicos sensibles por nombre
    if leaf in SENSITIVE_FIELD_HINTS or parent in SENSITIVE_FIELD_HINTS:
        return True

    # 3) Datos personales / PII por nombre de campo
    if leaf in PII_FIELD_HINTS or parent in PII_FIELD_HINTS:
        return True

    # 4) Patrones explícitos de PII
    if CURP_RE.match(value):
        return True

    if RFC_RE.match(value):
        return True

    # teléfono numérico simple
    if PHONE_RE.match(re.sub(r"[^\d+]", "", value)):
        return True

    # 5) Indicadores claros de secretos técnicos
    if _classify_sensitivity(value):
        return True

    return False

    # IMPORTANTE:
    # Si solo es el nombre de una variable/campo (por ejemplo "Password"),
    # no debe marcarse como hardcode sensible.
    # Ejemplo:
    # actions.PruebaVariable.inputs.variables[0].name = "Password"
    if leaf == "name":
        return False

    # 1) Todo correo literal sí entra como sensible
    if EMAIL_RE.search(value):
        return True

    # 2) Revisar SOLO nombres reales del campo, no todo el path completo
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

    # Si el campo realmente es sensible, entonces sí evaluar el valor
    if leaf in sensitive_fields or parent in sensitive_fields:
        return True

    # 3) Si el valor trae indicadores claros de secreto, sí entra
    # pero solo cuando no sea un simple nombre de variable/campo
    if _classify_sensitivity(value):
        return True

    return False


def _looks_parametrizable_literal(path: str, value: str) -> bool:
    value = (value or "").strip()
    path_low = (path or "").lower()
    leaf = _leaf_path_name(path)

    if not value:
        return False

    if _is_dynamic_reference(value):
        return False

    if _is_system_value(value):
        return False

    # Correos y sensibles NO entran como parametrizable
    if EMAIL_RE.search(value):
        return False

    if _classify_sensitivity(value):
        return False

    if CURP_RE.match(value) or RFC_RE.match(value):
        return False

    # Si por nombre parece PII, no es parametrizable
    if leaf in PII_FIELD_HINTS:
        return False

    field_looks_configurable = any(token in leaf for token in PARAMETRIZABLE_HINTS)

    if not field_looks_configurable:
        field_looks_configurable = any(f".{token}" in path_low for token in PARAMETRIZABLE_HINTS)

    if not field_looks_configurable:
        return False

    # URLs
    if URL_RE.search(value):
        return True

    # Rutas Windows / Unix
    if WINDOWS_PATH_RE.search(value) or UNIX_PATH_RE.search(value):
        return True

    # Archivos típicos
    if re.search(r"\.(xlsx|xls|docx|doc|csv|txt|json|pdf)$", value, re.IGNORECASE):
        return True

    # SharePoint / blobs / storage
    low_value = value.lower()
    if "sharepoint.com" in low_value or "blob.core.windows.net" in low_value:
        return True

    # IDs configurables típicos de source/drive/dataset/table
    if any(token in leaf for token in ("source", "drive", "dataset", "table")):
        return True

    if GUID_RE.match(value):
        return True

    # Paths o nombres configurables con slash, backslash o extensión
    if ("/" in value or "\\" in value or "." in value) and len(value) > 3:
        return True

    return False

    parametrizable_tokens = (
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
    )

    # El campo puede llamarse fileRPAEmployeeInformation,
    # CORPORATIVOFijoTemplate, tableRelacionUsuario, etc.
    field_looks_configurable = any(token in leaf for token in parametrizable_tokens)

    # También damos chance por si el path completo sugiere config
    if not field_looks_configurable:
        field_looks_configurable = any(f".{token}" in path_low for token in parametrizable_tokens)

    if not field_looks_configurable:
        return False

    # URLs
    if URL_RE.search(value):
        return True

    # Rutas
    if WINDOWS_PATH_RE.search(value) or UNIX_PATH_RE.search(value):
        return True

    # Archivos típicos
    if re.search(r"\.(xlsx|xls|docx|doc|csv|txt|json|pdf)$", value, re.IGNORECASE):
        return True

    # SharePoint / OneDrive / ids de configuración
    if "sharepoint.com" in value.lower():
        return True

    # Valores tipo source/drive/table/dataset aunque no traigan slash
    if any(token in leaf for token in ("source", "drive", "dataset", "table")):
        return True

    # Paths o nombres configurables con slash, backslash o extensión
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
    - Soporta:
        * type = Wait / Delay
        * inputs.interval.count + unit
        * strings tipo PT5M
    """
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

    # Caso 1: estructura típica interval.count / interval.unit
    interval = inputs.get("interval")
    if isinstance(interval, dict):
        count = interval.get("count")
        unit = interval.get("unit")

        if isinstance(count, (int, float)) or (isinstance(count, str) and count.strip()):
            findings.append(Finding(
                severity_level=2,
                rule_name="Delay/Wait",
                flow_name=flow_name,
                action_name=action_name,
                json_path=f"{base_path}.inputs.interval",
                reason="Se detectó una acción Delay/Wait con intervalo literal configurado.",
                evidence=f"count={count}, unit={unit}",
                impact="Aumenta tiempos de ejecución y puede volver frágil el flujo si cambian tiempos o latencias del entorno.",
                fix="Evitar delays innecesarios; si se requiere, justificar y parametrizar el intervalo o usar una condición de espera más robusta."
            ))
            return findings

    # Caso 2: string tipo PT5M o números literales en strings
    for path, s in _walk_values(inputs, f"{base_path}.inputs"):
        if re.search(r"\b\d+\b", s) or re.search(r"PT\d", s, re.IGNORECASE):
            findings.append(Finding(
                severity_level=2,
                rule_name="Delay/Wait",
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