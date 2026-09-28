from typing import Optional
from ..parsers import PARSERS
from ..parsers.base_parser import BaseParser

def get_parser(name: str) -> Optional[BaseParser]:
    """Retrieve a parser instance by its name or format identifier."""
    for parser in PARSERS:
        if parser.name == name or parser.format == name:
            return parser
    return None

def get_all_parsers() -> list[BaseParser]:
    """Retrieve all currently registered parser instances in the registry."""
    return list(PARSERS)

def register_parser(parser: BaseParser) -> None:
    """
    Onboard and register a new parser plugin into the active runtime registry.
    Ensures parser names remain unique.
    """
    if not any(p.name == parser.name for p in PARSERS):
        PARSERS.append(parser)

def unregister_parser(name: str) -> bool:
    """Unregister a parser plugin by its name."""
    global PARSERS
    for i, p in enumerate(PARSERS):
        if p.name == name:
            PARSERS.pop(i)
            return True
    return False
