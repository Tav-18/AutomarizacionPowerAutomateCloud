import os
import re
import uuid
from collections import Counter

from django.conf import settings
from django.http import FileResponse, Http404
from django.shortcuts import render, redirect

from .forms import UploadSolutionZipForm
from .services.zip_reader import save_upload, extract_zip, find_json_files
from .services.flow_parser import parse_flow_json
from .services.rules import run_all_rules, Finding
from .services.scoring import compute_score
from .services.excel_export import export_findings_to_xlsx

BASE_DIR = settings.BASE_DIR


def _flow_base(flow_name: str) -> str:
    base = os.path.basename(flow_name or "").strip()
    base = re.sub(r"\.json$", "", base, flags=re.I)
    return base.split("-", 1)[0].strip() if "-" in base else base.strip()


def _action_pretty(action: str) -> str:
    s = (action or "").replace("_", " ").strip()
    s_low = s.lower()
    for p in ["get data on rpa ", "get data on ", "get data "]:
        if s_low.startswith(p):
            s = s[len(p):].strip()
            break
    s = re.sub(r"\bcontent\b$", "", s, flags=re.I).strip()
    return s

def _action_key(flow_name: str, action_name: str) -> str:
    """
    Llave única real por actividad.
    No debe usar json_path del finding porque una misma acción
    puede tener varios findings en distintos paths internos.
    """
    return f"{flow_name or ''}||{action_name or ''}"


def upload_view(request):
    if request.method == "POST":
        form = UploadSolutionZipForm(request.POST, request.FILES)
        if form.is_valid():
            run_id = str(uuid.uuid4())
            project_id = form.cleaned_data.get("project_id", "").strip()

            uploads_dir = BASE_DIR / "uploads" / run_id
            reports_dir = BASE_DIR / "reports" / run_id
            os.makedirs(uploads_dir, exist_ok=True)
            os.makedirs(reports_dir, exist_ok=True)

            # 1) Guardar ZIP
            zip_path = str(uploads_dir / "solution.zip")
            save_upload(request.FILES["solution_zip"], zip_path)

            # 2) Extraer ZIP
            extracted_root = str(uploads_dir / "extracted")
            extract_zip(zip_path, extracted_root)

            # 3) Buscar JSON
            json_files = find_json_files(extracted_root)
            total_json = len(json_files)

            # 4) Parsear flows + correr reglas
            parsed_flows = []
            findings: list[Finding] = []
            total_actions = 0

            for jf in json_files:
                flow = parse_flow_json(jf)
                if not flow:
                    continue

                parsed_flows.append(flow)
                total_actions += len(flow.actions)

                # Reglas a nivel acción
                for act in flow.actions:
                    findings.extend(
                        run_all_rules(flow.flow_name, act.name, act.raw, act.json_path)
                    )

# 5) Score
            score, sev3, sev2, sev1, sem = compute_score(findings)

            # 6) Contar actividades únicas con incidencia
            flagged_actions = {
                _action_key(f.flow_name, f.action_name)
                for f in findings
            }
            flagged_actions_count = len(flagged_actions)
            passed_actions_count = max(0, total_actions - flagged_actions_count)

            passed_actions_pct = 0
            if total_actions > 0:
                passed_actions_pct = round((passed_actions_count / total_actions) * 100, 1)

            # 7) Serializar findings para session (máx 500)
            findings_dicts = [item.__dict__ for item in findings[:500]]

            # 7.1) Agregar target_pretty a cada finding
            for item in findings_dicts:
                flow_part = _flow_base(item.get("flow_name", ""))
                action_part = _action_pretty(item.get("action_name", ""))

                item["target_pretty"] = (
                    f"{flow_part} / {action_part}".strip(" /")
                    if action_part
                    else flow_part
                )

            # 8) Guardar resultados en sesión
            request.session[f"run:{run_id}"] = {
                "project_id": project_id,
                "score": score,
                "sem": sem,
                "e": sev3,
                "w": sev2,
                "i": sev1,
                "findings": findings_dicts,
                "total_json": total_json,
                "total_flows": len(parsed_flows),
                "total_actions": total_actions,
                "flagged_actions_count": flagged_actions_count,
                "passed_actions_count": passed_actions_count,
                "passed_actions_pct": passed_actions_pct,
            }
            return redirect("result", run_id=run_id)

    # GET o form inválido
    form = UploadSolutionZipForm()
    return render(request, "analyzer/upload.html", {"form": form})


def result_view(request, run_id: str):
    data = request.session.get(f"run:{run_id}")
    if not data:
        return render(
            request,
            "analyzer/result.html",
            {"run_id": run_id, "error": "No results for this run_id"},
        )

    findings = data.get("findings", [])

    counts = Counter([(f.get("rule_name") or "Unknown") for f in findings])
    top_rules = counts.most_common(6)

    return render(
        request,
        "analyzer/result.html",
        {
            "run_id": run_id,
            "project_id": data.get("project_id", ""),
            "score": data["score"],
            "sem": data["sem"],
            "e": data["e"],
            "w": data["w"],
            "i": data["i"],
            "findings": findings,
            "top_rules": top_rules,
            "total_json": data.get("total_json", 0),
            "total_flows": data.get("total_flows", 0),
            "total_actions": data.get("total_actions", 0),
            "flagged_actions_count": data.get("flagged_actions_count", 0),
            "passed_actions_count": data.get("passed_actions_count", 0),
            "passed_actions_pct": data.get("passed_actions_pct", 0),
        },
    )


def download_excel(request, run_id: str):
    data = request.session.get(f"run:{run_id}")
    if not data:
        raise Http404("No results for this run_id")

    reports_dir = BASE_DIR / "reports" / run_id
    os.makedirs(reports_dir, exist_ok=True)

    xlsx_path = reports_dir / "report.xlsx"

    export_findings_to_xlsx(
        out_path=str(xlsx_path),
        findings=data.get("findings", []),
        project_id=data.get("project_id", ""),
    )

    # ✅ Nombre del archivo con Project ID + run_id (más profesional)
    project_id = (data.get("project_id") or "SIN_ID").strip()
    project_id = project_id.replace(" ", "_").replace("/", "-")
    safe_project_id = re.sub(r"[^A-Za-z0-9_.-]", "", project_id)

    return FileResponse(
        open(xlsx_path, "rb"),
        as_attachment=True,
        filename=f"reporte_{safe_project_id}.xlsx",
)