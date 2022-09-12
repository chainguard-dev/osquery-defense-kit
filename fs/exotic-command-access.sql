-- A poor-mans replacement for file_events
-- Does not work if noatime is enabled.
SELECT path, atime, mtime,
    (strftime('%s', 'now') - ctime) AS mtime_age,
    (strftime('%s', 'now') - atime) AS atime_age
FROM file
WHERE path IN (
    '/usr/bin/bpftool',
    '/usr/bin/netcat',
    '/usr/bin/mkfifo',
    '/usr/bin/socat'
)
AND atime_age < 300
AND mtime_age > 300
