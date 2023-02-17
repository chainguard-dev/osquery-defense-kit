-- Catch applications running from unusual directories, such as /tmp (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1074/
--
-- false positives:
--   * programs running in alternative namespaces (Docker)
--
-- interval: 600
-- platform: linux
-- tags: process events
SELECT -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  p.cgroup_path AS p0_cgroup,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p1.euid, pe1.euid) AS p1_euid,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name
FROM process_events pe
  LEFT JOIN processes p ON pe.pid = pe.pid -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE pe.pid IN (
    SELECT pid
    FROM process_events
    WHERE time > (strftime('%s', 'now') -600)
      AND syscall = "execve"
      AND path NOT LIKE '/home/%'
      AND path NOT LIKE '/nix/%'
      AND path NOT LIKE '/opt/%'
      AND path NOT LIKE '/usr/local/%'
      AND path NOT LIKE '/snap/%'
      AND path NOT LIKE '%/.terraform/providers/%'
      AND path NOT LIKE '/tmp/%/bin'
      AND path NOT LIKE '/tmp/go-build%'
      AND REGEX_MATCH (path, '(.*)/', 1) NOT IN (
        '/',
        '/app',
        '/bin',
        '/ko-app',
        '/sbin',
        '/usr/bin',
        '/usr/sbin',
        '/usr/share/code',
        '/usr/share/teams',
        '/usr/lib/NetworkManager',
        '/usr/lib/firefox',
        '/usr/lib64/firefox',
        '/usr/libexec',
        '/usr/bin',
        '/usr/sbin',
        '/usr/share/teams/resources/app.asar.unpacked/node_modules/slimcore/bin'
      )
    GROUP BY pid
  )
  AND pe.time > (strftime('%s', 'now') -600)
  AND pe.syscall = "execve"
  AND p.cgroup_path NOT LIKE '/system.slice/docker-%'
  AND p.cgroup_path NOT LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
  AND p1.cgroup_path NOT LIKE '/system.slice/docker-%'
  AND p1.cgroup_path NOT LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
GROUP BY pe.pid