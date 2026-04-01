import os
import zipfile
from typing import List

def save_upload(uploaded_file, dst_path: str) -> None:
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, "wb") as f:
        for chunk in uploaded_file.chunks():
            f.write(chunk)

def extract_zip(zip_path: str, extract_to: str) -> str:
    os.makedirs(extract_to, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_to)
    return extract_to

def find_json_files(root_dir: str) -> List[str]:
    """
    Devuelve solo los JSON que estén dentro de una carpeta llamada 'Workflows'.

    Ejemplos válidos:
    - .../Workflows/flujo1.json
    - .../solution/Other/Workflows/flujo2.json

    No incluirá JSON fuera de esa carpeta.
    """
    matches: List[str] = []

    for root, _, files in os.walk(root_dir):
        rel_root = os.path.relpath(root, root_dir)
        rel_parts = [part.lower() for part in rel_root.replace("\\", "/").split("/")]

        # Solo procesar carpetas que contengan un segmento llamado "workflows"
        if "workflows" not in rel_parts:
            continue

        for name in files:
            if name.lower().endswith(".json"):
                matches.append(os.path.join(root, name))

    return matches