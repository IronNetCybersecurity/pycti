"""Common enums"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "FilterMode",
    "OrderingMode",
    "OrganizationFilter",
    "OrganizationsOrdering",
    "OrganizationReliability",
]


class FilterMode(str, Enum):
    """Filter mode enum"""

    and_ = "and"
    or_ = "or"


class OrderingMode(str, Enum):
    """Ordering mode enum"""

    asc = "asc"
    desc = "desc"


class OrganizationFilter(str, Enum):
    """Organization filter"""

    name = "name"
    aliases = "aliases"
    x_opencti_organization_type = "x_opencti_organization_type"
    x_opencti_reliability = "x_opencti_reliability"
    created = "created"
    modified = "modified"
    created_at = "created_at"
    updated_at = "updated_at"
    created_by = "createdBy"
    marked_by = "markedBy"
    labeled_by = "labelledBy"
    x_opencti_workflow_id = "x_opencti_workflow_id"
    revoked = "revoked"


class OrganizationsOrdering(str, Enum):
    """Organization ordering enum"""

    name = "name"
    confidence = "confidence"
    created = "created"
    modified = "modified"
    x_opencti_organization_type = "x_opencti_organization_type"
    x_opencti_workflow_id = "x_opencti_workflow_id"


class OrganizationReliability(str, Enum):
    """Organization reliability enum"""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"
