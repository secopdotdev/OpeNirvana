#!/usr/bin/env python3
"""gen-grafana-dashboards.py — generate the Observability dashboard suite.

Emits four linked Grafana dashboards as JSON into the provisioning folder.
Queries use metric names verified against the live Prometheus/Loki.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import grafana_panels as gp

_STACK = Path(__file__).resolve().parent.parent
_OUT = _STACK / "templates/grafana/provisioning/dashboards/observability"

# Reusable PromQL fragments (grounded in live metrics).
CPU_BUSY = '(1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100'
MEM_USED_PCT = '(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100'
MEM_USED_BYTES = '(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes)'
DISK_WORST_PCT = ('max(100 - (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"} '
                  '/ node_filesystem_size_bytes * 100))')
TARGETS_DOWN = 'count(up == 0) or vector(0)'
LOKI_ERR_15M = r'sum(count_over_time({container=~".+"} |~ `(?i)error|fatal|panic`[15m]))'

CONCERN = [(0, "green"), (80, "yellow"), (90, "red")]
DISK_CONCERN = [(0, "green"), (75, "yellow"), (85, "red")]


def build_fleet():
    panels = [
        gp.stat("Host CPU", CPU_BUSY, gp.GridPos(0, 0, 4, 4), unit="percent", thresholds=CONCERN),
        gp.stat("Host RAM", MEM_USED_PCT, gp.GridPos(4, 0, 4, 4), unit="percent", thresholds=CONCERN),
        gp.stat("Worst Disk", DISK_WORST_PCT, gp.GridPos(8, 0, 4, 4), unit="percent",
                thresholds=DISK_CONCERN),
        gp.stat("Targets Down", TARGETS_DOWN, gp.GridPos(12, 0, 4, 4),
                thresholds=[(0, "green"), (1, "red")]),
        gp.stat("PG / Redis up", "(min(pg_up) + min(redis_up))", gp.GridPos(16, 0, 4, 4),
                thresholds=[(0, "red"), (2, "green")]),
        gp.stat("Errors /15m", LOKI_ERR_15M, gp.GridPos(20, 0, 4, 4),
                thresholds=[(0, "green"), (1, "yellow"), (50, "red")]),
        gp.state_timeline("Connectivity (up per target)", "up", gp.GridPos(0, 4, 24, 5)),
        gp.gauge("CPU %", CPU_BUSY, gp.GridPos(0, 9, 6, 6), thresholds=CONCERN),
        gp.gauge("RAM %", MEM_USED_PCT, gp.GridPos(6, 9, 6, 6), thresholds=CONCERN),
        gp.timeseries("Host RAM used (raw)", [("RAM used", MEM_USED_BYTES)],
                      gp.GridPos(12, 9, 12, 6), unit="bytes"),
        gp.table("Top containers (mem bytes)",
                 'topk(10, container_memory_usage_bytes{name!=""})', gp.GridPos(0, 15, 12, 8),
                 unit="bytes"),
        gp.timeseries("Fleet error rate", [
            ("errors/min", r'sum(rate({container=~".+"} |~ `(?i)error`[5m]))')],
            gp.GridPos(12, 15, 12, 8)),
        gp.loki_table("Image updates available",
                      r'{job="image-updates"} | json | update_available=`true`',
                      gp.GridPos(0, 23, 24, 9)),
    ]
    panels[5]["targets"][0]["datasource"] = gp.LOKI  # Errors /15m is a Loki query
    panels[-2]["targets"][0]["datasource"] = gp.LOKI  # error-rate timeseries is Loki
    return gp.dashboard("Observability · Fleet Overview", "obs-fleet", panels)


def build_host():
    panels = [
        gp.timeseries("CPU busy %", [("busy", CPU_BUSY)], gp.GridPos(0, 0, 12, 7), unit="percent"),
        gp.timeseries("Load average", [("load1", "node_load1"), ("load5", "node_load5")],
                      gp.GridPos(12, 0, 12, 7)),
        gp.timeseries("Memory", [
            ("used", MEM_USED_BYTES), ("available", "node_memory_MemAvailable_bytes")],
            gp.GridPos(0, 7, 12, 7), unit="bytes"),
        gp.gauge("Filesystem used % ($mount)",
                 '100 - (node_filesystem_avail_bytes{mountpoint=~"$mount"} '
                 '/ node_filesystem_size_bytes * 100)', gp.GridPos(12, 7, 12, 7),
                 thresholds=DISK_CONCERN),
        gp.timeseries("Disk fill forecast (avail bytes; +24h)", [
            ("avail", 'node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"}'),
            ("predicted +24h", 'predict_linear(node_filesystem_avail_bytes'
             '{fstype!~"tmpfs|overlay|squashfs"}[6h], 86400)')],
            gp.GridPos(0, 14, 12, 7), unit="bytes"),
        gp.timeseries("Network", [
            ("rx", 'rate(node_network_receive_bytes_total[5m])'),
            ("tx", 'rate(node_network_transmit_bytes_total[5m])')],
            gp.GridPos(12, 14, 12, 7), unit="Bps"),
    ]
    vs = [gp.query_var("mount",
          'label_values(node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"}, mountpoint)',
          multi=True, include_all=True)]
    return gp.dashboard("Observability · Host (USE)", "obs-host", panels, variables=vs)


def build_services():
    g = gp.GridPos
    panels = [
        gp.timeseries("CPU cores ($service)", [
            ("$service", 'sum(rate(container_cpu_usage_seconds_total{name=~"$service"}[5m]))')],
            g(0, 0, 8, 7)),
        gp.timeseries("Memory ($service)", [
            ("used", 'container_memory_usage_bytes{name=~"$service"}'),
            ("limit", 'container_spec_memory_limit_bytes{name=~"$service"} > 0')],
            g(8, 0, 8, 7), unit="bytes"),
        gp.timeseries("Network ($service)", [
            ("rx", 'rate(container_network_receive_bytes_total{name=~"$service"}[5m])'),
            ("tx", 'rate(container_network_transmit_bytes_total{name=~"$service"}[5m])')],
            g(16, 0, 8, 7), unit="Bps"),
        gp.stat("Restarts (24h) ($service)",
                'changes(container_start_time_seconds{name=~"$service"}[24h])', g(0, 7, 6, 4),
                thresholds=[(0, "green"), (1, "yellow"), (5, "red")]),
        gp.timeseries("Error rate ($service)", [
            ("errors/min", r'sum(rate({container=~"$service"} |~ `(?i)error`[5m]))')],
            g(6, 7, 18, 4)),
        gp.logs("Logs ($service)", '{container=~"$service"}', g(0, 11, 24, 10)),
    ]
    panels[4]["targets"][0]["datasource"] = gp.LOKI
    vs = [gp.query_var("service", "label_values(container_last_seen, name)",
                       multi=False, include_all=False, regex="/^(?!\\d+$).+/")]
    return gp.dashboard("Observability · Per-Service", "obs-services", panels, variables=vs)


def build_security():
    AK = 'container="authentik-server"'
    fail_rate = r'sum(rate({%s} |~ `(?i)fail`[5m]))' % AK
    panels = [
        gp.timeseries("Authentik logins (Loki)", [
            ("success", r'sum(rate({%s} |~ `(?i)login.*success`[10m]))' % AK),
            ("failed", r'sum(rate({%s} |~ `(?i)(login.*fail|invalid)`[10m]))' % AK)],
            gp.GridPos(0, 0, 12, 7)),
        gp.timeseries("Auth failures vs anomaly band", [
            ("failed", fail_rate),
            ("avg(1h)", r'avg_over_time((%s)[1h:5m])' % fail_rate),
            ("+3σ", r'avg_over_time((%s)[1h:5m]) + 3 * stddev_over_time((%s)[1h:5m])'
                    % (fail_rate, fail_rate))],
            gp.GridPos(12, 0, 12, 7)),
        gp.timeseries("CrowdSec active decisions", [
            ("active", 'sum(cs_active_decisions) or vector(0)')], gp.GridPos(0, 7, 12, 7)),
        gp.timeseries("Fleet errors by container (top 8)", [
            ("{{container}}",
             r'topk(8, sum by (container) (rate({container=~".+"} |~ `(?i)error`[5m])))')],
            gp.GridPos(12, 7, 12, 7)),
        gp.logs("Recent critical errors",
                r'{container=~".+"} |~ `(?i)fatal|panic|critical`', gp.GridPos(0, 14, 24, 9)),
    ]
    for i in (0, 1, 3):  # Loki-backed timeseries
        for t in panels[i]["targets"]:
            t["datasource"] = gp.LOKI
    return gp.dashboard("Observability · Security & Auth", "obs-security", panels)


def build_all():
    return [build_fleet(), build_host(), build_services(), build_security()]


def main():
    ap = argparse.ArgumentParser(description="Generate Grafana observability dashboards")
    ap.add_argument("--output-dir", "-o", default=str(_OUT))
    args = ap.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    names = {"obs-fleet": "00-fleet-overview.json", "obs-host": "10-host.json",
             "obs-services": "20-services.json", "obs-security": "30-security-auth.json"}
    for d in build_all():
        (out / names[d["uid"]]).write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {names[d['uid']]}")


if __name__ == "__main__":
    main()
