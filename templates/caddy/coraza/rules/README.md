# OWASP CRS 4.x rule files

This directory is populated by `docker-host-config.sh` (or manually):

```bash
CRS_VERSION=v4.7.0
curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" \
  | tar -xz --strip-components=2 -C . "coreruleset-${CRS_VERSION#v}/rules"
```

Pinning: any 4.x release. Upgrade by bumping `CRS_VERSION` in `docker-host-config.sh`.
