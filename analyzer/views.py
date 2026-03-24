import os
import re
import uuid
import time
import shutil
import tempfile
from pathlib import Path
from io import BytesIO
from collections import Counter

from django.conf import settings
from django.http import FileResponse, Http404
from django.shortcuts import render, redirect

from .forms import UploadSolutionZipForm
from .services.zip_reader import save_upload, extract_zip, find_json_files
from .services.flow_parser import parse_flow_json
from .services.rules import run_all_rules, Finding
from .services.excel_export import export_findings_to_xlsx



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

PICKER_ROOT = Path(tempfile.gettempdir()) / "pa_flow_picker"


def _ensure_picker_root():
    PICKER_ROOT.mkdir(parents=True, exist_ok=True)


def _cleanup_old_picker_dirs(max_age_hours: int = 24):
    """
    Limpia carpetas temporales viejas por si alguien sube ZIP
    y nunca termina el análisis.
    """
    if not PICKER_ROOT.exists():
        return

    cutoff = time.time() - (max_age_hours * 3600)

    for child in PICKER_ROOT.iterdir():
        try:
            if child.is_dir() and child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
        except Exception:
            continue


def _display_flow_name_from_file(file_path: str) -> str:
    """
    Muestra solo la primera parte del nombre del archivo,
    antes del primer guion.
    """
    stem = Path(file_path).stem
    return stem.split("-", 1)[0].strip() if "-" in stem else stem.strip()


def _build_json_candidates(json_files: list[str], extracted_root: str) -> list[dict]:
    """
    Construye la lista que se mostrará en la pantalla de selección.
    """
    candidates = []

    for idx, jf in enumerate(sorted(json_files)):
        rel_path = os.path.relpath(jf, extracted_root).replace("\\", "/")
        display_name = _display_flow_name_from_file(jf)

        candidates.append({
            "id": str(idx),
            "display_name": display_name,
            "rel_path": rel_path,
            "full_path": jf,
        })

    return candidates



def upload_view(request):
    if request.method == "POST":
        form = UploadSolutionZipForm(request.POST, request.FILES)
        if form.is_valid():
            _ensure_picker_root()
            _cleanup_old_picker_dirs()

            pick_id = str(uuid.uuid4())
            project_id = form.cleaned_data.get("project_id", "").strip()

            pick_dir = PICKER_ROOT / pick_id
            extracted_root = pick_dir / "extracted"
            zip_path = pick_dir / "solution.zip"

            os.makedirs(pick_dir, exist_ok=True)
            os.makedirs(extracted_root, exist_ok=True)

            # 1) Guardar ZIP
            save_upload(request.FILES["solution_zip"], str(zip_path))

            # 2) Extraer ZIP
            extract_zip(str(zip_path), str(extracted_root))

            # 3) Buscar JSON
            json_files = find_json_files(str(extracted_root))
            if not json_files:
                shutil.rmtree(pick_dir, ignore_errors=True)
                return render(
                    request,
                    "analyzer/upload.html",
                    {
                        "form": form,
                        "error": "No JSON files were found inside the uploaded ZIP.",
                    },
                )

            # 4) Preparar lista para pantalla de selección
            candidates = _build_json_candidates(json_files, str(extracted_root))

            request.session[f"pick:{pick_id}"] = {
                "project_id": project_id,
                "pick_dir": str(pick_dir),
                "extracted_root": str(extracted_root),
                "candidates": candidates,
            }

            # 5) Ir a la pantalla para seleccionar JSONs
            return redirect("select_jsons", pick_id=pick_id)

    # GET o form inválido
    form = UploadSolutionZipForm()
    return render(request, "analyzer/upload.html", {"form": form})


def select_jsons_view(request, pick_id: str):
    data = request.session.get(f"pick:{pick_id}")
    if not data:
        return redirect("upload")

    candidates = data.get("candidates", [])
    project_id = data.get("project_id", "")

    if request.method == "POST":
        selected_ids = request.POST.getlist("selected_jsons")

        if not selected_ids:
            return render(
                request,
                "analyzer/select_jsons.html",
                {
                    "pick_id": pick_id,
                    "project_id": project_id,
                    "json_candidates": candidates,
                    "json_count": len(candidates),
                    "error": "Select at least one JSON file to continue.",
                },
            )

        candidate_map = {item["id"]: item for item in candidates}
        selected_items = [candidate_map[item_id] for item_id in selected_ids if item_id in candidate_map]

        if not selected_items:
            return render(
                request,
                "analyzer/select_jsons.html",
                {
                    "pick_id": pick_id,
                    "project_id": project_id,
                    "json_candidates": candidates,
                    "json_count": len(candidates),
                    "error": "The selected JSON files are not valid anymore. Please upload the ZIP again.",
                },
            )

        run_id = str(uuid.uuid4())
        findings: list[Finding] = []
        parsed_flows = []
        total_actions = 0
        total_json = len(selected_items)

        for item in selected_items:
            jf = item["full_path"]

            flow = parse_flow_json(jf)
            if not flow:
                continue

            parsed_flows.append(flow)
            total_actions += len(flow.actions)

            for act in flow.actions:
                findings.extend(
                    run_all_rules(flow.flow_name, act.name, act.raw, act.json_path)
                )


        flagged_actions = {
            _action_key(f.flow_name, f.action_name)
            for f in findings
        }
        flagged_actions_count = len(flagged_actions)
        passed_actions_count = max(0, total_actions - flagged_actions_count)

        passed_actions_pct = 0
        if total_actions > 0:
            passed_actions_pct = round((passed_actions_count / total_actions) * 100, 1)

        findings_sorted = sorted(
            findings,
            key=lambda f: (
                -f.severity_level,
                f.rule_name.lower(),
                f.flow_name.lower(),
                f.action_name.lower(),
            )
        )

        findings_dicts = [item.__dict__ for item in findings_sorted[:500]]

        for item in findings_dicts:
            flow_part = _flow_base(item.get("flow_name", ""))
            action_part = _action_pretty(item.get("action_name", ""))

            item["target_pretty"] = (
                f"{flow_part} / {action_part}".strip(" /")
                if action_part
                else flow_part
            )

        request.session[f"run:{run_id}"] = {
            "project_id": project_id,
            "findings": findings_dicts,
            "total_json": total_json,
            "total_flows": len(parsed_flows),
            "total_actions": total_actions,
            "flagged_actions_count": flagged_actions_count,
            "passed_actions_count": passed_actions_count,
            "passed_actions_pct": passed_actions_pct,
        }

        # limpiar carpeta temporal + sesión del picker
        pick_dir = data.get("pick_dir")
        if pick_dir:
            shutil.rmtree(pick_dir, ignore_errors=True)

        request.session.pop(f"pick:{pick_id}", None)

        return redirect("result", run_id=run_id)

    return render(
        request,
        "analyzer/select_jsons.html",
        {
            "pick_id": pick_id,
            "project_id": project_id,
            "json_candidates": candidates,
            "json_count": len(candidates),
        },
    )


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

    buffer = BytesIO()

    export_findings_to_xlsx(
        out_path=buffer,
        findings=data.get("findings", []),
        project_id=data.get("project_id", ""),
    )

    buffer.seek(0)

    project_id = (data.get("project_id") or "SIN_ID").strip()
    project_id = project_id.replace(" ", "_").replace("/", "-")
    safe_project_id = re.sub(r"[^A-Za-z0-9_.-]", "", project_id)

    return FileResponse(
        buffer,
        as_attachment=True,
        filename=f"reporte_{safe_project_id}.xlsx",
    )