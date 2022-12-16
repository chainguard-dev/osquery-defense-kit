-- Programs running with a hidden file path or process name
--
-- references:
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- tags: transient
-- platform: posix
SELECT
  p.pid,
  p.path,
  p.name,
  p.cmdline,
  p.cwd,
  p.euid,
  p.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  hash.sha256
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  (
    p.name LIKE '.%'
    OR f.filename LIKE '.%'
  )
  AND NOT f.path LIKE '/nix/store/%/%-wrapped'
  AND NOT (f.path LIKE '/nix/store/%' AND p.name LIKE '%-wrappe%')
