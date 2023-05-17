-- Programs running as root with a relative path
--
-- references:
--   * https://www.microsoft.com/en-us/security/blog/2022/12/21/microsoft-research-uncovers-new-zerobot-capabilities/
--
-- tags: transient process state
-- platform: posix
SELECT -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.start_time AS p0_start,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.start_time AS p1_start,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
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
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      euid < 500
      AND cmdline LIKE './%'
      AND NOT cmdline LIKE './out/osqtool-% %'
      AND NOT cgroup_path LIKE '/system.slice/docker-%'
  )
GROUP BY
  p0.pid
