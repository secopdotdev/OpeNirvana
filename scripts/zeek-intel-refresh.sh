#!/usr/bin/env bash
# Refresh Zeek Intel framework feeds. If a feed fails to download, keep the
# previous version in place. Run from cron nightly.
set -euo pipefail

INTEL_DIR=/dock/conf/zeek/intel
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$INTEL_DIR"

refresh() {
    local name="$1" url="$2" converter="$3"
    if curl --fail --silent --show-error --max-time 120 --output "$TMP/${name}.raw" "$url"; then
        if $converter "$TMP/${name}.raw" > "$TMP/${name}.tsv"; then
            mv "$TMP/${name}.tsv" "$INTEL_DIR/${name}.tsv"
            echo "$(date -Iseconds) refreshed: $name"
        else
            echo "$(date -Iseconds) convert failed: $name (kept previous)" >&2
        fi
    else
        echo "$(date -Iseconds) download failed: $name (kept previous)" >&2
    fi
}

# Converter: URLhaus CSV -> Zeek Intel TSV (domains only, simple form).
urlhaus_to_intel() {
    # URLhaus lines: "id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"
    awk -F'","' 'NR>1 && $1 !~ /^#/ {
        # Extract the URL field ($3), strip leading quote, extract host.
        sub(/^"/, "", $3)
        u=$3; sub(/^https?:\/\//, "", u); sub(/\/.*/, "", u); sub(/:.*/, "", u);
        if (u != "") printf "%s\tIntel::DOMAIN\turlhaus\t-\tT\t-\n", u
    }' "$1"
}
feodo_to_intel() {
    awk -F',' 'NR>1 && $1 !~ /^#/ && $2 != "" {
        printf "%s\tIntel::ADDR\tfeodo\t-\tT\t-\n", $2
    }' "$1"
}
crowdstrike_to_intel() {
    awk 'NF && $1 !~ /^#/ {
        printf "%s\tIntel::DOMAIN\tcrowdstrike\t-\tT\t-\n", $1
    }' "$1"
}

# Prepend Zeek Intel header to each file.
write_header() {
    printf "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.do_notice\tmeta.if_in\n" > "$1"
}

for base in urlhaus feodo crowdstrike-domains; do
    tmp_out="$TMP/${base}.tsv"
    write_header "$tmp_out"
done

refresh urlhaus     "https://urlhaus.abuse.ch/downloads/csv_recent/" "urlhaus_to_intel"
refresh feodo       "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" "feodo_to_intel"
refresh crowdstrike-domains "https://raw.githubusercontent.com/CrowdStrike/tickeys-io/main/badlist.txt" "crowdstrike_to_intel"

# Nudge Zeek to reload (cluster management framework).
docker exec zeek zeekctl deploy >/dev/null 2>&1 || echo "$(date -Iseconds) zeek reload failed" >&2
