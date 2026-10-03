import io
import zipfile
from pathlib import Path
from app.main import app as fastapi_app, download_sample_logs
import app.enhanced_main  # registers all 16 parsers and installs enhanced detector
from app.core.pipeline import process_lines
from app.core.ingestion import read_text_lines

SAMPLE_KIT_DIR = Path(__file__).resolve().parents[3] / "sample_logs" / "UniLogX-Sample-Logs"

def test_download_sample_logs_handler():
    response = download_sample_logs()
    assert response.status_code == 200
    assert response.media_type == "application/zip"
    
    zip_path = Path(response.path)
    assert zip_path.exists()
    assert zip_path.stat().st_size > 0
    
    # Verify zip content structure
    with zipfile.ZipFile(zip_path) as zf:
        namelist = zf.namelist()
        assert any("README.txt" in name for name in namelist)
        assert any("cisco_asa" in name for name in namelist)
        assert any("nginx" in name for name in namelist)
        assert any("cloud_json" in name for name in namelist)
        assert any("syslog" in name for name in namelist)
        assert any("unknown_quarantine" in name for name in namelist)

def test_download_sample_logs_route_registered():
    route_paths = [r.path for r in fastapi_app.routes]
    assert "/UniLogX-Sample-Logs.zip" in route_paths

def test_judge_kit_parser_samples_e2e():
    assert SAMPLE_KIT_DIR.exists()
    
    # Test valid parsers
    parser_folders = [
        p for p in SAMPLE_KIT_DIR.iterdir() 
        if p.is_dir() and p.name != "unknown_quarantine"
    ]
    assert len(parser_folders) == 16, f"Expected 16 parser directories, found {len(parser_folders)}"
    
    total_parsed = 0
    for folder in sorted(parser_folders):
        for file in folder.glob("*"):
            if not file.is_file():
                continue
            content = file.read_bytes()
            lines = read_text_lines(content, file.name)
            res = process_lines(lines, source_file=file.name)
            assert res["processed"] > 0, f"Expected events processed for {folder.name}/{file.name}"
            assert res["quarantined"] == 0, f"Expected 0 quarantined for {folder.name}/{file.name}, got {res['quarantined']}"
            total_parsed += res["processed"]
    
    assert total_parsed == 160

def test_judge_kit_quarantine_samples_e2e():
    quarantine_dir = SAMPLE_KIT_DIR / "unknown_quarantine"
    assert quarantine_dir.exists()
    
    quarantine_files = sorted(quarantine_dir.glob("*.log"))
    assert len(quarantine_files) == 3
    
    total_quarantined = 0
    for file in quarantine_files:
        content = file.read_bytes()
        lines = read_text_lines(content, file.name)
        res = process_lines(lines, source_file=file.name)
        assert res["quarantined"] > 0, f"Expected quarantined logs for {file.name}"
        assert res["processed"] == 0, f"Expected 0 processed for {file.name}, got {res['processed']}"
        total_quarantined += res["quarantined"]
        
    assert total_quarantined == 15
