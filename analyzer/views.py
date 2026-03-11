import os
import uuid
from collections import Counter

import pdfkit
from django.conf import settings
from django.http import FileResponse, Http404
from django.shortcuts import render, redirect
from django.template.loader import render_to_string

from .forms import UploadSolutionZipForm
from .services.zip_reader import save_upload, extract_zip, find_json_files
from .services.flow_parser import parse_flow_json
from .services.rules import run_all_rules, Finding
from .services.scoring import compute_score

BASE_DIR = settings.BASE_DIR


def upload_view(request):
    if request.method == "POST":
        form = UploadSolutionZipForm(request.POST, request.FILES)
        if form.is_valid():
            run_id = str(uuid.uuid4())

            # ✅ Project ID (del form)
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

                for act in flow.actions:
                    findings.extend(
                        run_all_rules(flow.flow_name, act.name, act.raw, act.json_path)
                    )

            # 5) Score
            # compute_score(findings) debe regresar: score, sev3, sev2, sev1, sem
            score, sev3, sev2, sev1, sem = compute_score(findings)

            # 6) Reporte HTML (para PDF)
            css_path = BASE_DIR / "analyzer" / "static" / "analyzer" / "styles_print.css"
            inline_css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""

            findings_dicts = [item.__dict__ for item in findings[:500]]

            report_html = render_to_string(
                "analyzer/report.html",
                {
                    "inline_css": inline_css,
                    "run_id": run_id,              # si quieres ocultarlo en pantalla, en PDF puede quedar
                    "project_id": project_id,      # ✅ nuevo
                    "score": score,
                    "sem": sem,
                    # ✅ mantenemos nombres para templates actuales
                    "e": sev3,   # severity 3 (crítico)
                    "w": sev2,   # severity 2
                    "i": sev1,   # severity 1 (bajo)
                    "total_json": total_json,
                    "total_flows": len(parsed_flows),
                    "total_actions": total_actions,
                    "findings": findings_dicts,
                },
            )

            report_html_path = reports_dir / "report.html"
            report_html_path.write_text(report_html, encoding="utf-8")

            # 7) Guardar en sesión
            request.session[f"run:{run_id}"] = {
                "project_id": project_id,  # ✅ nuevo
                "score": score,
                "sem": sem,
                "e": sev3,
                "w": sev2,
                "i": sev1,
                "findings": findings_dicts,
                "total_json": total_json,
                "total_flows": len(parsed_flows),
                "total_actions": total_actions,
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

    # ✅ Top repeated rules (Broken Rule)
    counts = Counter([(f.get("rule_name") or "Unknown") for f in findings])
    top_rules = counts.most_common(6)

    return render(
        request,
        "analyzer/result.html",
        {
            "run_id": run_id,
            "project_id": data.get("project_id", ""),  # ✅ nuevo
            "score": data["score"],
            "sem": data["sem"],
            "e": data["e"],
            "w": data["w"],
            "i": data["i"],
            "findings": findings,
            "top_rules": top_rules,  # ✅ nuevo
            "total_json": data.get("total_json", 0),
            "total_flows": data.get("total_flows", 0),
            "total_actions": data.get("total_actions", 0),
        },
    )


def download_pdf(request, run_id: str):
    html_path = BASE_DIR / "reports" / run_id / "report.html"
    if not html_path.exists():
        raise Http404("Report HTML not found")

    pdf_path = BASE_DIR / "reports" / run_id / "report.pdf"

    wk_path = getattr(settings, "WKHTMLTOPDF_PATH", None)
    if not wk_path or not os.path.exists(wk_path):
        raise Http404("wkhtmltopdf not installed or WKHTMLTOPDF_PATH is wrong")

    config = pdfkit.configuration(wkhtmltopdf=wk_path)

    options = {
        "page-size": "A4",
        "encoding": "UTF-8",
        "margin-top": "10mm",
        "margin-right": "10mm",
        "margin-bottom": "10mm",
        "margin-left": "10mm",
        "enable-local-file-access": None,
        "quiet": "",
    }

    pdfkit.from_file(str(html_path), str(pdf_path), configuration=config, options=options)

    return FileResponse(
        open(pdf_path, "rb"),
        as_attachment=True,
        filename=f"report_{run_id}.pdf",
    )