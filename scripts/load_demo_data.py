from pathlib import Path
import requests
BASE='http://localhost:8000/api/v1/upload'
for path in Path('sample_logs').glob('*'):
    if path.is_file():
        with path.open('rb') as f:
            r=requests.post(BASE,files={'file':(path.name,f)})
        print(path.name,r.status_code,r.text)
