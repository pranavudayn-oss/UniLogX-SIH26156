import requests
r=requests.get('http://localhost:8000/api/v1/events/export/csv')
Path='unilogx-events.csv'
open(Path,'wb').write(r.content)
print(Path)
