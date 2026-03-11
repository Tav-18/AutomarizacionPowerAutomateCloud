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
    matches: List[str] = []
    for root, _, files in os.walk(root_dir):
        for name in files:
            if name.lower().endswith(".json"):
                matches.append(os.path.join(root, name))
    return matches