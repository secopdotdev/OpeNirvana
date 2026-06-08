-- your-org security analytics schema
-- All tables live in the `your-org` database with 90-day TTL on raw event data.

CREATE DATABASE IF NOT EXISTS your-org;

-- Least-privilege write user for the Vector log ingestion pipeline.
-- Password is set via CLICKHOUSE_VECTOR_PASSWORD env var passed to the container.
CREATE USER IF NOT EXISTS vector IDENTIFIED WITH sha256_password BY '${CLICKHOUSE_VECTOR_PASSWORD}';
GRANT INSERT ON your-org.caddy_access_logs TO vector;
GRANT INSERT ON your-org.coraza_events TO vector;

-- Raw Caddy access log events from Vector
CREATE TABLE IF NOT EXISTS your-org.caddy_access_logs
(
    ts           DateTime,
    request_host String,
    request_uri  String,
    method       String,
    status       Int32,
    duration     Float64,
    bytes_sent   Int64,
    client_ip    String,
    user_agent   String,
    request_id   String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, client_ip)
TTL ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Coraza WAF events (blocks, anomalies, rule matches)
CREATE TABLE IF NOT EXISTS your-org.coraza_events
(
    ts          DateTime,
    client_ip   String,
    rule_id     Int32,
    rule_msg    String,
    severity    String,
    request_uri String,
    method      String,
    action      String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, client_ip, rule_id)
TTL ts + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Daily blocked IP summary (for dashboards — lightweight aggregation target)
CREATE TABLE IF NOT EXISTS your-org.daily_blocked_ips
(
    day       Date,
    client_ip String,
    count     UInt64
)
ENGINE = SummingMergeTree(count)
PARTITION BY toYYYYMM(day)
ORDER BY (day, client_ip)
TTL day + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- Materialized view: auto-populate daily_blocked_ips from coraza_events
CREATE MATERIALIZED VIEW IF NOT EXISTS your-org.mv_daily_blocked_ips
TO your-org.daily_blocked_ips
AS
SELECT
    toDate(ts)  AS day,
    client_ip,
    count()     AS count
FROM your-org.coraza_events
WHERE action = 'deny'
GROUP BY day, client_ip;
