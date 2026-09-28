# Parser Guide

Implement `BaseParser`, provide `name`, `format`, and `description`, then implement `can_parse()` and `parse_line()`. Register the parser in `app/parsers/__init__.py`. Prefer returning source-specific fields and let `normalizer.py` perform canonical mapping.
