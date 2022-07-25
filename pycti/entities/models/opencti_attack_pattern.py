"""Attack Pattern models"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import Field

from .opencti_common import CustomModel
from .opencti_enums import FilterMode, OrderingMode


class AttackPatternsOrdering(str, Enum):
    """Attack-Pattern ordering enum"""

    x_mitre_id = "x_mitre_id"
    name = "name"
    created = "created"
    modified = "modified"
    created_at = "created_at"
    updated_at = "updated_at"
    x_opencti_workflow_id = "x_opencti_workflow_id"


class AttackPatternsFilter(str, Enum):
    """Attack-Pattern filter enum"""

    name = "name"
    aliases = "aliases"
    created = "created"
    modified = "modified"
    created_at = "created_at"
    updated_at = "updated_at"
    x_mitre_id = "x_mitre_id"
    created_by = "createdBy"
    marked_by = "markedBy"
    labeled_by = "labelledBy"
    mitigated_by = "mitigatedBy"
    revoked = "revoked"
    x_opencti_workflow_id = "x_opencti_workflow_id"


class AttackPatternReadInput(CustomModel):
    """Query: attackPattern(...)"""

    id: str


class AttackPatternListInput(CustomModel):
    """Query: attackPatterns(...)"""

    first: Optional[int] = Field(description="Retrieve the first N rows")
    after: Optional[str] = Field(description="The row to continue pagination at")
    order_by: AttackPatternsOrdering = Field(
        alias="orderby",
        description="Ordering field",
    )
    order_mode: OrderingMode = Field(
        alias="orderMode",
        description="Ordering mode",
    )
    filters: Optional[List[AttackPatternsFilter]] = Field(description="Filters")
    filter_mode: Optional[FilterMode] = Field(
        alias="filterMode",
        description="Filtering mode",
    )
    search: Optional[str] = Field(description="Search terms")


class AttackPatternCreateInput(CustomModel):
    """Mutation: attackPatternAdd(...)"""

    stix_id: Optional[str]
    x_opencti_stix_ids: Optional[List[str]]
    name: str
    description: Optional[str]
    aliases: Optional[List[str]]
    revoked: Optional[bool]
    lang: Optional[str]
    confidence: Optional[int]
    x_mitre_platforms: Optional[List[str]]
    x_mitre_permissions_required: Optional[List[str]]
    x_mitre_detection: Optional[str]
    x_mitre_id: Optional[str]
    created_by: Optional[str] = Field(alias="createdBy")
    object_marking: Optional[List[str]] = Field(alias="objectMarking")
    object_label: Optional[List[str]] = Field(alias="objectLabel")
    kill_chain_phases: Optional[List[str]] = Field(alias="killChainPhases")
    external_references: Optional[List[str]] = Field(alias="externalReferences")
    created: Optional[str]
    modified: Optional[str]
    client_mutation_id: Optional[str] = Field(alias="clientMutationId")
    update: Optional[bool]
