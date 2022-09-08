-- Detect poorly done timestamping
-- Alert on programs running that are unusually old
SELECT p.path, p.cmdline, p.cwd,
    ((strftime('%s', 'now') - f.ctime) / 86400) AS ctime_age_days,
    ((strftime('%s', 'now') - f.ctime) / 86400) AS mtime_age_days,
    ((strftime('%s', 'now') - f.btime) / 86400) AS btime_age_days
FROM processes p
    JOIN file f ON p.path = f.path
WHERE (
        ctime_age_days > 1000
        OR mtime_age_days > 1000
    )
AND path NOT LIKE "%/opt/brackets/Brackets%"