import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

@dataclass
class FlowAction:
    name: str
    type: str
    raw: Dict[str, Any]
    json_path: str

@dataclass
class ParsedFlow:
    flow_name: str
    source_file: str
    actions: List[FlowAction]
    raw: Dict[str, Any]

def _guess_flow_name(raw: Dict[str, Any], fallback: str) -> str:
    return (
        raw.get("properties", {}).get("displayName")
        or raw.get("name")
        or raw.get("properties", {}).get("friendlyName")
        or fallback
    )

def parse_flow_json(file_path: str) -> Optional[ParsedFlow]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return None

    workflow_raw = raw

    # Caso 1: JSON directo con properties/definition o definition
    definition = (
        workflow_raw.get("properties", {}).get("definition")
        or workflow_raw.get("definition")
        or {}
    )
    actions_dict = definition.get("actions") or {}

    # Caso 2: ARM template / deploymentTemplate con resources[]
    if not isinstance(actions_dict, dict) or not actions_dict:
        resources = raw.get("resources")
        if isinstance(resources, list):
            for resource in resources:
                if not isinstance(resource, dict):
                    continue

                resource_type = str(resource.get("type", "") or "").lower()
                if resource_type == "microsoft.logic/workflows":
                    workflow_raw = resource
                    definition = (
                        resource.get("properties", {}).get("definition")
                        or resource.get("definition")
                        or {}
                    )
                    actions_dict = definition.get("actions") or {}
                    if isinstance(actions_dict, dict) and actions_dict:
                        break

    if not isinstance(actions_dict, dict) or not actions_dict:
        return None

    actions: List[FlowAction] = []
    for action_name, action_body in actions_dict.items():
        if not isinstance(action_body, dict):
            continue
        actions.append(
            FlowAction(
                name=action_name,
                type=str(action_body.get("type", "") or ""),
                raw=action_body,
                json_path=f"actions.{action_name}",
            )
        )

    flow_name = _guess_flow_name(workflow_raw, fallback=file_path.split("\\")[-1])
    return ParsedFlow(
        flow_name=flow_name,
        source_file=file_path,
        actions=actions,
        raw=workflow_raw,
    )

    flow_name = _guess_flow_name(raw, fallback=file_path.split("\\")[-1])
    return ParsedFlow(flow_name=flow_name, source_file=file_path, actions=actions, raw=raw)