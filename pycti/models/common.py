"""OpenCTI common model implementations"""
from pydantic import BaseModel

__all__ = [
    "CustomModel",
]


class CustomModel(BaseModel):
    """Custom Pydantic base model"""

    class Config:
        """Model config"""

        allow_population_by_field_name = True
