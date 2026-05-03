# Zeek Intel feeds

Populated nightly by `scripts/zeek-intel-refresh.sh` (Task 16). Each `.tsv`
file is a Zeek Intel file per the docs:
<https://docs.zeek.org/en/current/frameworks/intel.html>

Formats downloaded:
- `urlhaus.tsv` — URLhaus indicator feed
- `feodo.tsv` — Feodo tracker IP/domain feed
- `crowdstrike-domains.tsv` — CrowdStrike free malicious domain list

If any feed fails to download, the previous version is retained (never
leave Zeek with an empty Intel framework).
