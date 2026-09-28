from abc import ABC, abstractmethod
from typing import Any, Optional

class BaseParser(ABC):
    name: str = "base"
    display_name: str = "Base Parser"
    vendor: str = "Generic"
    format: str = "unknown"
    version: str = "1.0"
    supported_source: str = "general"
    description: str = "Base parser"
    supported_fields: list[str] = []
    mapping_file: Optional[str] = None
    status: str = "Active"

    @abstractmethod
    def can_parse(self, text: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse_line(self, line: str) -> dict[str, Any]:
        raise NotImplementedError

    def to_registry_dict(self, processed_count: int = 0) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": getattr(self, "display_name", self.name.replace("_", " ").title()),
            "vendor": getattr(self, "vendor", "Generic"),
            "version": getattr(self, "version", "1.0"),
            "format": self.format,
            "supported_format": self.format,
            "source": getattr(self, "supported_source", "general"),
            "supported_source": getattr(self, "supported_source", "general"),
            "description": self.description,
            "supported_fields": getattr(self, "supported_fields", []),
            "mapping_file": getattr(self, "mapping_file", None),
            "status": getattr(self, "status", "Active"),
            "enabled": True,
            "processed_count": processed_count,
        }
