CREATE TABLE IF NOT EXISTS rampart_events
(
    timestamp DateTime,
    event_type String,
    ip String,
    data_float Float64,
    data_int Int64,
    data_string String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, event_type);
