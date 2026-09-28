from app.parsers import PARSERS

def test_all_parsers_have_identity():
    assert len(PARSERS) >= 5
    for p in PARSERS:
        assert p.name and p.format and p.description
