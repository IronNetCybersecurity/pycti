"""OpenCTI entity CRUD operations"""

import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from stix2.canonicalization.Canonicalize import canonicalize

from ..api.opencti_api_client import AnyDict, ProcessedResultsDict

__all__ = [
    "OpenCTIObjectBase",
    "StixObjectBase",
]

SCO_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7"


class OpenCTIObjectBase(ABC):
    """Abstract CRUD object base"""

    @classmethod
    def _generate_id(cls, prefix: str, data: Dict[str, Any]) -> str:
        """
        Generate a uuid5 identifier
        :param prefix: Identifier prefix
        :param data: Namespace data
        :return: A uuid5 identifier
        """
        data = canonicalize(data, utf8=False)
        id = str(uuid.uuid5(uuid.UUID(SCO_NAMESPACE), data))
        return f"{prefix}--{id}"

    @abstractmethod
    def list(self, **kwargs) -> ProcessedResultsDict:
        """List objects"""

    @abstractmethod
    def read(self, **kwargs) -> Optional[AnyDict]:
        """Read an object"""

    @abstractmethod
    def create(self, **kwargs) -> Optional[AnyDict]:
        """Create an object"""

    @abstractmethod
    def import_from_stix2(self, **kwargs) -> Optional[AnyDict]:
        """Import an object from a STIX2 object"""


class StixObjectBase(ABC):
    """Abstract CRUD stix object base"""
