-- Slow query to find root programs with an open socket and few shared libraries
--
-- false positives:
--   * some minimalist daemons
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent process state seldom
-- platform: macos
SELECT
    p.uid,
    p.euid,
    pos.protocol,
    pos.pid,
    pos.remote_address,
    pos.local_address,
    pos.local_port,
    pos.remote_port,
    p.name,
    p.start_time,
    p.parent,
    p.cgroup_path,
    p.path,
    pos.state,
    GROUP_CONCAT(pmm.path) AS libs,
    COUNT(DISTINCT pmm.path) AS lib_count,
    CONCAT(
        MIN(p.euid, 500),
        ',',
        p.name,
        ',',
        p.path
    ) AS exception_key
FROM
    processes p
    -- For some reason, joining this table increases the runtime by 30X
    -- LEFT JOIN signature s ON p.path = s.path
    JOIN process_memory_map pmm ON p.pid = pmm.pid
    JOIN process_open_sockets pos ON p.pid = pos.pid
WHERE
    p.pid IN (
        SELECT
            processes.pid
        FROM
            processes
            JOIN process_open_sockets ON processes.pid = process_open_sockets.pid
            AND family != 1
        WHERE
            processes.path NOT LIKE '/System/%'
            AND processes.path NOT LIKE '/Library/Apple/%'
            AND processes.path NOT LIKE '/usr/libexec/%'
            AND processes.path NOT LIKE '/usr/sbin/%'
            AND processes.path NOT LIKE '/sbin/%'
            AND processes.path NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
            AND processes.path NOT LIKE '/usr/bin/%'
            AND processes.path NOT LIKE '/nix/store/%/bin/nix'
            AND processes.path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
            AND processes.path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/Kolide.app/Contents/MacOS/launcher'
            AND processes.start_time > (strftime('%s', 'now') -604800)
            AND processes.resident_size < 200000000
        GROUP BY
            processes.path
    )
    AND pmm.path LIKE "%.dylib"
    AND exception_key NOT IN ()
GROUP BY
    pos.pid
HAVING
    lib_count IN (1, 2)