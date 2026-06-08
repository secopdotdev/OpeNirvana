#!/bin/bash
docker exec caddy wget -qO- http://127.0.0.1:2019/config/apps/http/servers/srv0/routes 2>/dev/null | \
python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data:
    m = str(r.get('match', ''))
    h = str(r.get('handle', ''))
    if 'n8n' in m.lower() or 'n8n' in h.lower():
        print('MATCH:', m[:200])
        print('HANDLE:', h[:200])
        print()
"
echo "---"
docker exec caddy sh -c 'echo $N8N_SUBDOMAIN'
