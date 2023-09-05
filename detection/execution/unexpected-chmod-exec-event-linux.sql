-- Things that call chmod to set executable permissions
--
-- references:
--   * https://www.microsoft.com/en-us/security/blog/2022/05/19/rise-in-xorddos-a-deeper-look-at-the-stealthy-ddos-malware-targeting-linux-devices/
--
-- false positives:
--   * loads of them
--
-- tags: transient process events
-- platform: linux
-- interval: 300
SELECT
  IFNULL(
    REGEX_MATCH (TRIM(pe.cmdline), '.* (/.*)', 1),
    CONCAT (
      pe.cwd,
      '/',
      REGEX_MATCH (TRIM(pe.cmdline), '.* (.*)', 1)
    )
  ) AS f_path,
  f.mode AS f_mode,
  f.type AS f_type,
  hash.sha256 AS f_hash,
  magic.data AS f_magic,
  -- Child
  pe.path AS p0_path,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
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
  ) AS p2_name,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS exception_key
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  -- Wow, you can do that?
  LEFT JOIN file f ON IFNULL(
    REGEX_MATCH (TRIM(pe.cmdline), '.* (/.*)', 1),
    CONCAT (
      pe.cwd,
      '/',
      REGEX_MATCH (TRIM(pe.cmdline), '.* (.*)', 1)
    )
  ) = f.path
  LEFT JOIN hash ON f.path = hash.path
  LEFT JOIN magic ON f.path = magic.path
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  pe.pid IN (
    SELECT DISTINCT
      pid
    FROM
      process_events
    WHERE
      time > (strftime('%s', 'now') -300)
      AND syscall = "execve"
      AND (
        cmdline LIKE '%chmod% 7%'
        OR cmdline LIKE '%chmod% +rwx%'
        OR cmdline LIKE '%chmod% +x%'
        OR cmdline LIKE '%chmod% u+x%'
        OR cmdline LIKE '%chmod% a+x%'
      )
      AND cmdline NOT LIKE 'chmod 777 /app/%'
      AND cmdline NOT LIKE 'chmod 700 /tmp/apt-key-gpghome.%'
      AND cmdline NOT LIKE 'chmod 700 /home/%/snap/%/%/.config'
  )
  AND pe.time > (strftime('%s', 'now') -300)
  AND pe.syscall = "execve"
  AND f.type != 'directory'
  AND p1_cgroup NOT LIKE '/system.slice/docker-%'
  AND p1_cgroup NOT LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
  AND p2_cgroup NOT LIKE '/system.slice/docker-%'
  AND p2_cgroup NOT LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
GROUP BY
  p0_pid
