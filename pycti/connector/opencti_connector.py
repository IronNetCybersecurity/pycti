"""OpenCTI connector spec"""

from __future__ import annotations

from enum import Enum
from typing import List, TypedDict


class ConnectorType(str, Enum):
    """Connector types"""

    # From remote sources to OpenCTI stix2
    EXTERNAL_IMPORT = "EXTERNAL_IMPORT"

    # From OpenCTI file system to OpenCTI stix2
    # Scope: Files mime types to support (application/json, ...)
    INTERNAL_IMPORT_FILE = "INTERNAL_IMPORT_FILE"

    # From OpenCTI stix2 to OpenCTI stix2
    # Scope: Entity types to support (Report, Hash, ...)
    INTERNAL_ENRICHMENT = "INTERNAL_ENRICHMENT"

    # From OpenCTI stix2 to OpenCTI file system
    # Scope: Files mime types to generate (application/pdf, ...)
    INTERNAL_EXPORT_FILE = "INTERNAL_EXPORT_FILE"

    # Read the stream and do something
    STREAM = "STREAM"


class OpenCTIConnector:
    """OpenCTI connector spec"""

    def __init__(
        self,
        connector_id: str,
        connector_name: str,
        connector_type: str,
        scope: str,
        auto: bool,
        only_contextual: bool,
    ):
        """
        Constructor
        :param connector_id: A valid uuid4 as the connector ID
        :param connector_name: The connector name
        :param connector_type: A valid connector type (see `ConnectorType`)
        :param scope: Connector scope
        :param auto:
        :param only_contextual:
        :raises ValueError: If the connector type is not valid
        """
        self.id = connector_id
        self.name = connector_name
        self.type = ConnectorType(connector_type)
        if self.type is None:
            raise ValueError("Invalid connector type: " + connector_type)

        if scope and len(scope) > 0:
            self.scope = scope.split(",")
        else:
            self.scope = []

        self.auto = auto
        self.only_contextual = only_contextual

    def to_input(self) -> ConnectorInput:
        """
        Connector input to use in an API query
        :return: dict with connector data
        :rtype: dict
        """
        return {
            "input": {
                "id": self.id,
                "name": self.name,
                "type": self.type.name,
                "scope": self.scope,
                "auto": self.auto,
                "only_contextual": self.only_contextual,
            }
        }


class ConnectorInput(TypedDict):
    """Connector input"""

    input: ConnectorInputDetails


class ConnectorInputDetails(TypedDict):
    """Connector input details"""

    id: str
    name: str
    type: str
    scope: List[str]
    auto: bool
    only_contextual: bool
