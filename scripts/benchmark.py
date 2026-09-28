import time
from pathlib import Path
from backend.app.core.pipeline import process_lines
path=Path('sample_logs/nginx_access.log')
lines=path.read_text().splitlines()*1000
start=time.perf_counter(); result=process_lines(lines,'benchmark'); elapsed=time.perf_counter()-start
print({'lines':len(lines),'seconds':round(elapsed,4),'events':result['processed']})
