-- Slow query to find root programs with an open socket and few shared libraries
--
-- false positives:
--   * some minimalist daemons
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent process state seldom
-- platform: linux
SELECT p.uid,
    p.euid,
    pos.protocol,
    pos.pid,
    pos.remote_address,
    pos.local_address,
    pos.local_port,
    pos.remote_port,
    p.start_time,
    p.name,
    p.parent,
    p.cgroup_path,
    p.path,
    pos.state,
    GROUP_CONCAT(DISTINCT pmm.path) AS libs,
    COUNT(DISTINCT pmm.path) AS lib_count
FROM processes p
    JOIN process_open_sockets pos ON p.pid = pos.pid AND pos.family != 1
    JOIN process_memory_map pmm ON pos.pid = pmm.pid 
WHERE p.pid IN (
        SELECT pid
        FROM processes
        WHERE path NOT IN (
                '/usr/bin/containerd',
                '/usr/bin/fusermount3',
                '/usr/sbin/acpid',
                '/usr/bin/dash',
                '/usr/bin/docker',
                '/usr/sbin/mcelog',
                '/usr/bin/docker-proxy',
                '/usr/bin/cat',
                '/usr/lib/electron/chrome-sandbox',
                '/usr/bin/i3blocks'
            )
            AND name NOT IN ('chrome_crashpad', 'dhcpcd', 'Brackets-node')
        GROUP BY processes.path
    )
    AND pmm.path LIKE "%.so.%"
GROUP BY pos.pid -- libc.so, ld-linux
HAVING lib_count IN (1, 2)