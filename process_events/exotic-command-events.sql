-- Ported from exotic-commands
-- Events version of sketchy-fetchers
-- Designed for execution every 5 minutes (where the parent may still be around)
SELECT p.pid,
    p.path,
    p.cmdline,
    p.mode,
    p.cwd,
    p.euid,
    p.parent,
    p.syscall,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid,
    hash.sha256 AS parent_sha256
FROM uptime, process_events p
    LEFT JOIN processes pp ON p.parent = pp.pid
    LEFT JOIN hash ON pp.path = hash.path
WHERE p.time > (strftime('%s', 'now') -300)
    AND p.path IN (
        '/usr/bin/bpftool',
        '/usr/bin/netcat',
        '/usr/bin/mkfifo',
        '/usr/bin/socat',
        '/usr/bin/kmod'
    )
    -- Things that could reasonably happen at boot.
    AND NOT (
        p.path = '/usr/bin/kmod'
        AND uptime.total_seconds < 15
    )