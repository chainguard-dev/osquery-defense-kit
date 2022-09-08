-- Detect poorly done timestamping
-- Alert on programs running that are over a year old
SELECT *,
    ((strftime('%s', 'now') - f.ctime) / 86400) AS ctime_age_days,
    ((strftime('%s', 'now') - f.ctime) / 86400) AS mtime_age_days,
    ((strftime('%s', 'now') - f.btime) / 86400) AS btime_age_days
FROM processes p
    JOIN file f ON p.path = f.path
WHERE (
        ctime_age_days > 982
        OR mtime_age_days > 982
        OR (
            f.btime > 1
            AND btime_age_days > 1200
        )
    )