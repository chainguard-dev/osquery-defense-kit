-- Programs running as root with a relative path (event-based)
--
-- references:
--   * https://www.microsoft.com/en-us/security/blog/2022/12/21/microsoft-research-uncovers-new-zerobot-capabilities/
--
-- platform: posix
-- interval: 300
-- tags: process events
SELECT
  pe.pid,
  pe.path,
  pe.mode,
  pe.cwd,
  pe.euid,
  pe.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  pp.euid AS parent_euid,
  phash.sha256 AS parent_sha256,
  gp.cmdline AS gparent_cmd,
  hash.sha256 AS sha256,
  p.cgroup_path AS cgroup,
  pp.cgroup_path AS parent_cgroup,
  gp.cgroup_path AS gparent_cgroup
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = pe.pid
  LEFT JOIN processes pp ON pe.parent = p.pid
  LEFT JOIN processes gp ON pp.parent = gp.pid
  LEFT JOIN hash ON pe.path = hash.path
  LEFT JOIN hash phash ON pp.path = hash.path
WHERE
  pe.euid < 500 AND pe.cmdline LIKE './%'
  AND pe.time > (strftime('%s', 'now') -300)
