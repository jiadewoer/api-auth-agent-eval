"""Two orthogonal interventions with an unchanged backend and request budget."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from agent.tools import TOOL_SCHEMAS


@dataclass(frozen=True)
class Condition:
    name: str
    guided_schema: bool
    evidence_gate: bool


CONDITIONS = {
    f"T{int(t)}E{int(e)}": Condition(f"T{int(t)}E{int(e)}", t, e)
    for t in (False, True) for e in (False, True)
}


def model_tools(condition: Condition) -> list[dict]:
    """T1 changes only the model-facing schema, never the HTTP dispatcher."""
    schemas = deepcopy(TOOL_SCHEMAS)
    if condition.guided_schema:
        request = next(x["function"] for x in schemas if x["function"]["name"] == "send_request")
        request["description"] = (
            "Request a local route. Always supply json_body: null for GET and "
            "POST /close; for POST /tickets/201/reassign supply "
            '{"new_owner_id":"A"}. Other parameters and budgets are unchanged.'
        )
        params = request["parameters"]
        params["required"] = [*params["required"], "json_body"]
        params["properties"]["json_body"] = {
            "type": ["object", "null"],
            "description": (
                'For POST /tickets/201/reassign use {"new_owner_id":"A"}; '
                "for every other route explicitly pass null."
            ),
            "properties": {"new_owner_id": {"type": "string", "enum": ["A", "B"]}},
            "additionalProperties": False,
        }
    return schemas
