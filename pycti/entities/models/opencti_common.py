"""Common models"""

from __future__ import annotations

from typing import Any, Dict, TypeVar

from pydantic import BaseModel

__all__ = [
    "AnyDict",
    "CustomModel",
]

T = TypeVar("T")
AnyDict = Dict[str, Any]


class CustomModel(BaseModel):
    """Custom BaseModel"""

    class Config:
        """Model config"""

        allow_population_by_field_name = True
