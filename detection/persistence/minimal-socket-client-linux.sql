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
SELECT pos.protocol,
    pos.pid,
    pos.remote_address,
    pos.local_address,
    pos.local_port,
    pos.remote_port,
    pos.state,
    GROUP_CONCAT(DISTINCT pmm.path) AS libs,
    COUNT(DISTINCT pmm.path) AS lib_count,
    -- Child
    p0.pid AS p0_pid,
    p0.path AS p0_path,
    p0.name AS p0_name,
    p0.start_time AS p0_start,
    p0.cmdline AS p0_cmd,
    p0.cwd AS p0_cwd,
    p0.cgroup_path AS p0_cgroup,
    p0.euid AS p0_euid,
    p0_hash.sha256 AS p0_sha256
FROM processes p0
    JOIN process_open_sockets pos ON p0.pid = pos.pid
    JOIN process_memory_map pmm ON p0.pid = pmm.pid
    LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
WHERE p0.path != '' -- optimization: focus on longer running processes
    AND p0.start_time < (strftime('%s', 'now') - 900)
    AND p0.path NOT IN (
        '/usr/bin/containerd',
        '/usr/bin/fusermount3',
        '/usr/sbin/acpid',
        '/usr/bin/dash',
        '/usr/bin/docker',
        '/usr/sbin/mcelog',
        '/usr/libexec/docker/docker-proxy',
        '/usr/bin/docker-proxy',
        '/usr/bin/cat',
        '/usr/lib/electron/chrome-sandbox',
        '/usr/bin/i3blocks'
    )
    AND p0.name NOT IN ('chrome_crashpad', 'dhcpcd', 'stern', 'Brackets-node') -- optimization: minimalistic daemons typically only run 1 pid per path
    AND p0.path NOT LIKE '/home/%/go/bin/%'
    AND pos.family != 1
    AND pos.pid > 0
    AND pos.state != 'LISTEN'
    AND pmm.path LIKE "%.so.%"
GROUP BY pos.pid -- libc.so, ld-linux
HAVING lib_count IN (1, 2)