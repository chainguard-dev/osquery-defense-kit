-- Programs running as root with a relative path
--
-- references:
--   * https://www.microsoft.com/en-us/security/blog/2022/12/21/microsoft-research-uncovers-new-zerobot-capabilities/
--
-- tags: transient process rapid state
-- platform: linux
SELECT
  p.pid,
  p.name,
  p.path,
  p.euid,
  p.gid,
  p.cgroup_path,
  f.ctime,
  f.directory AS dirname,
  p.cmdline,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON hash.path = p.path
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE
  p.euid < 500 AND p.cmdline LIKE './%'
