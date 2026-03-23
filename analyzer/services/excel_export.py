from __future__ import annotations

import os
import re
from typing import Dict, List

from openpyxl import Workbook
from openpyxl.styles import Font, Alignment, PatternFill
from openpyxl.utils import get_column_letter


# =========================
# 1) Headers (ENGLISH)
# =========================
HEADERS = ["Title", "Internal Path", "Target", "impact area", "Suggestion"]


# =========================
# 2) Helpers: Flow / Action formatting
# =========================
def flow_base(flow_name: str) -> str:
    """
    'AutonomousAgentsIsaGPO_2-79C3BC7D-...json' -> 'AutonomousAgentsIsaGPO_2'
    """
    if not flow_name:
        return ""
    base = os.path.basename(flow_name).strip()
    base = re.sub(r"\.json$", "", base, flags=re.IGNORECASE)
    if "-" in base:
        base = base.split("-", 1)[0]
    return base.strip()


def action_pretty(action_name: str) -> str:
    """
    Reglas solicitadas:
    - '_' -> ' '
    - quitar prefijos tipo "Get data on RPA ..." (y variantes)
    - opcional: quitar "content" al final
    """
    if not action_name:
        return ""

    s = action_name.replace("_", " ").strip()

    # Quitar prefijos comunes (ajusta si detectas otros)
    prefixes = [
        "Get data on RPA ",
        "Get data on rpa ",
        "Get data on ",
        "Get data ",
    ]
    s_low = s.lower()
    for p in prefixes:
        if s_low.startswith(p.lower()):
            s = s[len(p) :].strip()
            break

    # Opcional: quitar "content" al final
    s = re.sub(r"\bcontent\b$", "", s, flags=re.IGNORECASE).strip()
    return s


def make_target(flow_name: str, action_name: str) -> str:
    """
    Formato solicitado:
    'AutonomousAgentsIsaGPO_2 / Información de empleo API'
    """
    fb = flow_base(flow_name)
    ap = action_pretty(action_name)
    return f"{fb} / {ap}".strip(" /")


# =========================
# 3) Mapping: rule_name -> catálogo (Suggestion en Español)
#    (MVP Cloud)
# =========================
RULE_CATALOG: Dict[str, Dict[str, object]] = {
    "Hardcode sensible": {
        "impact_area": "C - Hard Code",
        "title": "Hard Code",
        "suggestion_es": (
            "Evitar valores sensibles hardcodeados. "
            "Mover a un repositorio seguro (por ejemplo variables de entorno protegidas, "
            "Key Vault o connection references) según el estándar."
        ),
    },
    "Parametrizable": {
        "impact_area": "M - Parametrizable",
        "title": "Parametrizable",
        "suggestion_es": (
            "Mover este valor a un mecanismo parametrizable (por ejemplo variables de entorno, "
            "parámetros o configuración central) según el estándar."
        ),
    },
    "Naming de actividades": {
        "impact_area": "L - Nombre de Actividades",
        "title": "Nombre de Actividades",
        "suggestion_es": (
            "Renombrar la actividad a un título descriptivo y único, alineado al manual."
        ),
    },
    "Manejo de errores (RunAfter)": {
        "impact_area": "E - Manejo de errores",
        "title": "Manejo de errores",
        "suggestion_es": (
            "Configurar runAfter para estados failed/timedOut/canceled y agregar manejo de error "
            "(registro, notificación y/o terminación controlada)."
        ),
    },
    "Delay/Wait": {
        "impact_area": "E - Retrasos",
        "title": "Retrasos",
        "suggestion_es": (
            "Evitar demoras fijas; preferir condiciones/esperas robustas o parametrizar la demora "
            "con justificación."
        ),
    },
    "Nomenclatura de variables": {
        "impact_area": "L - Variables",
        "title": "Variable Naming",
        "suggestion_es": (
            "Renombrar la variable siguiendo el estándar Cloud: "
            "Bln/Int/Flt/Str/Obj/Arr + UpperCamelCase."
        ),
    },
    "Prefijos de parámetros entre flujos": {
        "impact_area": "L - Parámetros",
        "title": "Flow Parameters",
        "suggestion_es": (
            "Renombrar parámetros usando in_, out_ o io_ y el tipo de dato "
            "según el estándar definido."
        ),
    },
    "Recomendaciones de escritura": {
        "impact_area": "L - Escritura",
        "title": "Writing Rules",
        "suggestion_es": (
            "Usar ASCII, sin acentos ni caracteres especiales no permitidos, "
            "y mantener nombres consistentes."
        ),
    },
    "Nomenclatura de variables": {
    "impact_area": "L - Variables",
    "title": "Variable Naming",
    "suggestion_es": (
        "Renombrar la variable siguiendo el estándar Cloud: "
        "Bln/Int/Flt/Str/Obj/Arr + UpperCamelCase."
        ),
    },
    "Nomenclatura de flujos y subflujos": {
        "impact_area": "L - Flujos",
        "title": "Flow Naming",
        "suggestion_es": (
            "Renombrar el flujo o subflujo usando UpperCamelCase, sin espacios, "
            "sin acentos y sin caracteres especiales."
        ),
    },
}



def map_rule(rule_name: str) -> Dict[str, str]:
    """
    Si llega una regla no mapeada, cae a default.
    """
    if not rule_name:
        rule_name = "Finding"

    mapping = RULE_CATALOG.get(rule_name)
    if mapping:
        return {
            "impact_area": str(mapping["impact_area"]),
            "title": str(mapping["title"]),
            "suggestion": str(mapping["suggestion_es"]),
        }

    return {
        "impact_area": "M - Requerimientos",
        "title": rule_name,
        "suggestion": (
            "Revisar la incidencia y alinearla al manual de buenas prácticas interno."
        ),
    }


# =========================
# 4) Internal Path real del proyecto
#    - usa flow_file_relpath si existe
#    - concatena json_path
# =========================
def build_internal_path(f: dict) -> str:
    """
    Preferencia:
    1) Si existe flow_file_relpath -> "Workflows/xxxx.json :: actions...."
    2) Si no existe -> usar json_path, pero sin '_' para que sea legible
    """
    json_path = (f.get("json_path") or "").strip()
    flow_rel = (f.get("flow_file_relpath") or "").strip()

    # ✅ hacer json_path más legible (quitar guión bajo)
    json_path_clean = json_path.replace("_", " ")

    if flow_rel and json_path_clean:
        return f"{flow_rel} :: {json_path_clean}"
    if flow_rel:
        return flow_rel
    return json_path_clean


# =========================
# 5) Build rows for Excel
# =========================
def build_findings_rows(findings: List[dict]) -> List[List[str]]:
    rows: List[List[str]] = []

    for f in findings:
        rule_name = (f.get("rule_name") or "").strip()
        flow_name = (f.get("flow_name") or "").strip()
        action_name = (f.get("action_name") or "").strip()

        mapping = map_rule(rule_name)

        title = mapping["title"]                     # EN
        internal_path = build_internal_path(f)        # REAL PATH si existe
        target = make_target(flow_name, action_name) # FlowBase / ActionPretty
        impact_area = mapping["impact_area"]          # catálogo

        # Suggestion en Español + detalle opcional (reason)
        reason = (f.get("reason") or "").strip()
        suggestion = mapping["suggestion"]
        if reason:
            suggestion = mapping["suggestion"]

        rows.append([title, internal_path, target, impact_area, suggestion])

    return rows


# =========================
# 6) Export
# =========================
def export_findings_to_xlsx(
    out_path,
    findings: List[dict],
    project_id: str = "",
) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"

    # Header
    ws.append(HEADERS)

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="4F46E5")  # morado sobrio
    header_alignment = Alignment(vertical="center", horizontal="left", wrap_text=True)

    for col_idx, _ in enumerate(HEADERS, start=1):
        cell = ws.cell(row=1, column=col_idx)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment

    # Rows
    rows = build_findings_rows(findings)
    for r in rows:
        ws.append(r)

    # Freeze + Filters
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(HEADERS))}{max(1, len(rows) + 1)}"

    # Column widths
    col_widths = {
        1: 26,  # Title
        2: 55,  # Internal Path
        3: 44,  # Target
        4: 22,  # impact area
        5: 85,  # Suggestion
    }
    for col_idx, w in col_widths.items():
        ws.column_dimensions[get_column_letter(col_idx)].width = w

    # Wrap in long cols
    wrap_cols = [2, 3, 5]
    for row in ws.iter_rows(min_row=2, max_row=len(rows) + 1):
        for idx in wrap_cols:
            row[idx - 1].alignment = Alignment(wrap_text=True, vertical="top")

    # Meta sheet (opcional)
    meta = wb.create_sheet("Meta")
    meta.append(["Project ID", project_id])
    meta.append(["Total findings", len(findings)])

    wb.save(out_path)