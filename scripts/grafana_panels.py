#!/usr/bin/env python3
"""grafana_panels — tiny helpers to build Grafana dashboard JSON.

Stdlib only; each helper returns a plain dict so dashboards serialize with
json.dumps. Datasource UIDs are fixed: 'prometheus' (pinned) and 'loki'.
"""
from __future__ import annotations
from dataclasses import dataclass

PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}


@dataclass
class GridPos:
    x: int
    y: int
    w: int
    h: int

    def d(self) -> dict:
        return {"x": self.x, "y": self.y, "w": self.w, "h": self.h}


def _thresholds(steps):
    return {"mode": "absolute",
            "steps": [{"value": (None if v == 0 else v), "color": c} for v, c in steps]}


def _target(expr, legend=None, instant=False):
    t = {"datasource": PROM, "expr": expr, "refId": "A"}
    if legend is not None:
        t["legendFormat"] = legend
    if instant:
        t["instant"] = True
    return t


def stat(title, expr, grid: GridPos, unit="none", thresholds=None, instant=True):
    th = thresholds or [(0, "green")]
    return {
        "type": "stat", "title": title, "gridPos": grid.d(), "datasource": PROM,
        "targets": [_target(expr, instant=instant)],
        "fieldConfig": {"defaults": {"unit": unit, "thresholds": _thresholds(th),
                                     "color": {"mode": "thresholds"}}, "overrides": []},
        "options": {"colorMode": "background", "graphMode": "area",
                    "reduceOptions": {"calcs": ["lastNotNull"]}},
    }


def gauge(title, expr, grid: GridPos, unit="percent", thresholds=None, maximum=100):
    th = thresholds or [(0, "green"), (80, "yellow"), (90, "red")]
    return {
        "type": "gauge", "title": title, "gridPos": grid.d(), "datasource": PROM,
        "targets": [_target(expr, instant=True)],
        "fieldConfig": {"defaults": {"unit": unit, "min": 0, "max": maximum,
                                     "thresholds": _thresholds(th)}, "overrides": []},
    }


def timeseries(title, series, grid: GridPos, unit="none", thresholds=None, stack=False):
    targets = []
    for i, (legend, expr) in enumerate(series):
        t = _target(expr, legend=legend)
        t["refId"] = chr(ord("A") + i)
        targets.append(t)
    defaults = {"unit": unit, "custom": {"fillOpacity": 10,
                "stacking": {"mode": "normal" if stack else "none"}}}
    if thresholds:
        defaults["thresholds"] = _thresholds(thresholds)
        defaults["custom"]["thresholdsStyle"] = {"mode": "line"}
    return {"type": "timeseries", "title": title, "gridPos": grid.d(),
            "datasource": PROM, "targets": targets,
            "fieldConfig": {"defaults": defaults, "overrides": []}}


def table(title, expr, grid: GridPos, unit="none"):
    return {"type": "table", "title": title, "gridPos": grid.d(), "datasource": PROM,
            "targets": [_target(expr, instant=True)],
            "transformations": [{"id": "labelsToFields", "options": {}}],
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []}}


def state_timeline(title, expr, grid: GridPos):
    return {"type": "state-timeline", "title": title, "gridPos": grid.d(),
            "datasource": PROM, "targets": [_target(expr, legend="{{job}} {{instance}}")],
            "fieldConfig": {"defaults": {"mappings": [
                {"type": "value", "options": {"0": {"text": "DOWN", "color": "red"},
                                              "1": {"text": "UP", "color": "green"}}}]},
                "overrides": []}}


def logs(title, logql, grid: GridPos):
    return {"type": "logs", "title": title, "gridPos": grid.d(), "datasource": LOKI,
            "targets": [{"datasource": LOKI, "expr": logql, "refId": "A"}],
            "options": {"showTime": True, "wrapLogMessage": True,
                        "sortOrder": "Descending"}}


def loki_table(title, logql, grid: GridPos, keep=("service", "current", "latest", "repo")):
    """Table panel over a Loki JSONL stream: extract JSON fields from the log
    line, keep `keep` columns, and group by service (last value) so the table
    shows the most recent snapshot — one row per service."""
    group_fields = {"service": {"aggregations": [], "operation": "groupby"}}
    for f in keep:
        if f != "service":
            group_fields[f] = {"aggregations": ["lastNotNull"], "operation": "aggregate"}
    return {
        "type": "table", "title": title, "gridPos": grid.d(), "datasource": LOKI,
        "targets": [{"datasource": LOKI, "expr": logql, "queryType": "range", "refId": "A"}],
        "transformations": [
            {"id": "extractFields", "options": {"source": "Line", "format": "json"}},
            {"id": "groupBy", "options": {"fields": group_fields}},
            {"id": "organize", "options": {"renameByName": {
                "service": "Service", "current (lastNotNull)": "Current",
                "latest (lastNotNull)": "Latest", "repo (lastNotNull)": "Repo"}}},
        ],
        "fieldConfig": {"defaults": {}, "overrides": []},
    }


def row(title, y, collapsed=False, panels=None):
    return {"type": "row", "title": title, "collapsed": collapsed,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
            "panels": panels or []}


def query_var(name, query, label=None, multi=False, include_all=False, regex=""):
    return {"type": "query", "name": name, "label": label or name.title(),
            "datasource": PROM, "query": query, "refresh": 2, "sort": 1,
            "multi": multi, "includeAll": include_all, "regex": regex,
            "current": {}, "options": []}


def const_var(name, value):
    return {"type": "constant", "name": name, "query": str(value),
            "current": {"text": str(value), "value": str(value)}, "hide": 2}


def dashboard(title, uid, panels, tags=None, variables=None, refresh="30s"):
    pid = 0
    for p in panels:
        pid += 1
        p["id"] = pid
        for sub in p.get("panels", []):
            pid += 1
            sub["id"] = pid
    return {
        "uid": uid, "title": title, "tags": tags or ["observability"],
        "timezone": "browser", "schemaVersion": 39, "refresh": refresh,
        "time": {"from": "now-6h", "to": "now"},
        "templating": {"list": variables or []},
        "panels": panels,
    }
