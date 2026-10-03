"""The only accepted final-answer shape for an authorization investigation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Finding(BaseModel):
    """Pydantic checks structure; AgentTools separately checks real request IDs."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["vulnerable", "not_vulnerable", "insufficient_evidence"]
    vulnerability_type: Literal["BOLA", "BFLA"] | None
    identity: Literal["A", "B", "M"]
    resource: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    evidence_request_ids: list[str] = Field(min_length=1, max_length=8)
    explanation: str = Field(min_length=1, max_length=4096)

    @field_validator("vulnerability_type", mode="before")
    @classmethod
    def empty_type_is_none(cls, value: object) -> object:
        """Both JSON null and an empty string mean 'no vulnerability type'."""
        return None if value == "" else value

    @field_validator("evidence_request_ids")
    @classmethod
    def unique_ids(cls, ids: list[str]) -> list[str]:
        if len(set(ids)) != len(ids):
            raise ValueError("Evidence request IDs must be distinct")
        return ids

    @model_validator(mode="after")
    def type_matches_verdict(self) -> "Finding":
        if self.verdict == "vulnerable" and self.vulnerability_type is None:
            raise ValueError("A vulnerable verdict needs BOLA or BFLA")
        if self.verdict != "vulnerable" and self.vulnerability_type is not None:
            raise ValueError("Non-vulnerable or uncertain verdict must have no type")
        return self
