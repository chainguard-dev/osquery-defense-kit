-- Currently running program with Linux red flags
-- 
-- reference:
--   * bpfdoor (old)
--
-- tags: persistent
-- interval: 7200
-- platform: linux
SELECT
  yara.strings,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.start_time AS p0_start,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.start_time AS p1_start,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.start_time AS p2_start,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  JOIN yara ON p0.path = yara.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.start_time > (strftime('%s', 'now') - 7200)
  AND
  yara.sigrule = '    
    rule syscalls {
    strings:
        $inet_ntoa = "inet_ntoa"
        $listen = "listen"
        $connect = "connect"
        $execve = "execve"
    condition:
        filesize < 10MB and $execve in (0..8192) and 2 of them
}'
  AND yara.count > 0
  AND yara.path NOT IN (
    '/usr/sbin/auditd',
    '/usr/bin/dbus-broker-launch',
    '/usr/sbin/mcelog'
  )
