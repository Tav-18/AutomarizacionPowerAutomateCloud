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


def _collect_actions_recursive(
    actions_dict: Dict[str, Any],
    base_path: str,
    out: List[FlowAction],
) -> None:
    """
    Recorre acciones de forma recursiva para capturar:
    - actions
    - branches[*].actions
    - else.actions
    - defaultCase.actions
    - cases[*].actions
    - acciones anidadas en foreach/scope/if/switch
    """
    if not isinstance(actions_dict, dict):
        return

    for action_name, action_body in actions_dict.items():
        if not isinstance(action_body, dict):
            continue

        current_path = f"{base_path}.{action_name}" if base_path else action_name

        out.append(
            FlowAction(
                name=action_name,
                type=str(action_body.get("type", "") or ""),
                raw=action_body,
                json_path=current_path,
            )
        )

        # 1) acciones hijas directas
        nested_actions = action_body.get("actions")
        if isinstance(nested_actions, dict) and nested_actions:
            _collect_actions_recursive(
                nested_actions,
                f"{current_path}.actions",
                out,
            )

        # 2) rama else
        else_block = action_body.get("else")
        if isinstance(else_block, dict):
            else_actions = else_block.get("actions")
            if isinstance(else_actions, dict) and else_actions:
                _collect_actions_recursive(
                    else_actions,
                    f"{current_path}.else.actions",
                    out,
                )

        # 3) branches (algunos tipos de control usan branches)
        branches = action_body.get("branches")
        if isinstance(branches, list):
            for i, branch in enumerate(branches):
                if not isinstance(branch, dict):
                    continue
                branch_actions = branch.get("actions")
                if isinstance(branch_actions, dict) and branch_actions:
                    _collect_actions_recursive(
                        branch_actions,
                        f"{current_path}.branches[{i}].actions",
                        out,
                    )

        # 4) cases de switch
        cases = action_body.get("cases")
        if isinstance(cases, dict):
            for case_name, case_body in cases.items():
                if not isinstance(case_body, dict):
                    continue
                case_actions = case_body.get("actions")
                if isinstance(case_actions, dict) and case_actions:
                    _collect_actions_recursive(
                        case_actions,
                        f"{current_path}.cases.{case_name}.actions",
                        out,
                    )

        # 5) defaultCase de switch
        default_case = action_body.get("defaultCase")
        if isinstance(default_case, dict):
            default_actions = default_case.get("actions")
            if isinstance(default_actions, dict) and default_actions:
                _collect_actions_recursive(
                    default_actions,
                    f"{current_path}.defaultCase.actions",
                    out,
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
    _collect_actions_recursive(actions_dict, "actions", actions)

    flow_name = _guess_flow_name(workflow_raw, fallback=file_path.split("\\")[-1])

    return ParsedFlow(
        flow_name=flow_name,
        source_file=file_path,
        actions=actions,
        raw=workflow_raw,
    )