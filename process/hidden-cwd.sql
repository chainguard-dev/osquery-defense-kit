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
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256
FROM
  processes p
  JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = hash.path
WHERE
  p.cwd LIKE "%/.%"
  AND NOT (
    p.cwd LIKE "%/.local/share%"
    OR p.cwd LIKE "%/.vscode/extensions%"
    OR p.cwd LIKE "/Users/%/.%"
    OR p.cwd LIKE "/home/%/.%"
    OR p.cwd LIKE "/Library/Apple/System/Library/InstallerSandboxes/.PKInstallSandboxManager-SystemSoftware/%"
    OR p.cwd LIKE "/tmp/.wine-%/server-%"
    OR p.name IN ('bindfs', 'wineserver')
    OR p.path = "/usr/libexec/dirhelper"
  )
