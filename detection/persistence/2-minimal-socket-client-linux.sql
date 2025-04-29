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
SELECT
  pos.protocol,
  pos.pid,
  pos.remote_address,
  pos.local_address,
  pos.local_port,
  pos.remote_port,
  pos.state,
  GROUP_CONCAT(DISTINCT pmm.path) AS libs,
  COUNT(DISTINCT pmm.path) AS lib_count,
  -- Child
  p0.path AS proc_path,
  p0.name AS proc_name,
  p0.start_time AS proc_start,
  p0.cmdline AS proc_cmd,
  p0.cwd AS porc_cwd,
  p0.cgroup_path AS proc_cgroup,
  p0.euid AS proc_euid,
  p0_hash.sha256 AS sha256
FROM
  processes p0
  JOIN process_open_sockets pos ON p0.pid = pos.pid
  JOIN process_memory_map pmm ON p0.pid = pmm.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
WHERE
  p0.path != '' -- optimization: focus on longer running processes
  AND p0.start_time < (strftime('%s', 'now') - 900)
  AND p0.path NOT IN (
    '/opt/bitnami/redis/bin/redis-server',
    '/opt/java/openjdk/bin/java',
    '/usr/bin/cat',
    '/usr/bin/containerd',
    '/usr/bin/dash',
    '/usr/bin/daprd',
    '/usr/bin/docker',
    '/usr/bin/docker-proxy',
    '/usr/bin/fusermount3',
    '/usr/bin/i3blocks',
    '/usr/bin/kas',
    '/usr/bin/k3s',
    '/usr/bin/vmalert',
    '/usr/lib/electron/chrome-sandbox',
    '/usr/lib/snapd/snapd',
    '/usr/libexec/docker/docker-proxy',
    '/usr/local/bin/containerd',
    '/usr/local/bin/gitary',
    '/usr/sbin/acpid',
    '/usr/sbin/mcelog'
  )
  AND p0.name NOT IN (
    'Brackets-node',
    'chrome_crashpad',
    'launcher',
    'dhcpcd',
    'gitsign-credent',
    'gitaly',
    'kas',
    'k9s',
    'redis-server',
    'stern'
  ) -- optimization: minimalistic daemons typically only run 1 pid per path
  AND p0.path NOT LIKE '/home/%/go/bin/%'
  AND pos.family != 1
  AND pos.pid > 0
  AND pos.state != 'LISTEN'
  AND pmm.path LIKE "%.so.%"
  AND NOT (
    pos.local_address = "127.0.0.1"
    AND pos.remote_address = "127.0.0.1"
  )
  AND NOT proc_cgroup in ('/system.slice/snapd.service')
  AND NOT proc_cgroup LIKE '/system.slice/docker-%'
GROUP BY
  pos.pid -- libc.so, ld-linux
HAVING
  lib_count IN (1, 2)
