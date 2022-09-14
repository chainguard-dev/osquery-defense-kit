-- A poor-mans replacement for file_events
-- Does not work if noatime is enabled.
SELECT path,
    atime,
    mtime,
    (strftime('%s', 'now') - ctime) AS mtime_age,
    (strftime('%s', 'now') - atime) AS atime_age,
    (atime_age - uptime.total_seconds) AS atime_after_boot
FROM file,
    uptime
WHERE path IN (
        '/usr/bin/bpftool',
        '/usr/bin/netcat',
        '/usr/bin/mkfifo',
        '/usr/bin/socat',
        '/usr/bin/kmod',
    )
    AND atime_age < 300
    AND mtime_age > 300
    AND NOT (
        path = '/usr/bin/kmod'
        AND atime_after_boot < 15
    )