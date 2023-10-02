-- Programs running with a hidden file path or process name
--
-- references:
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- tags: transient
-- platform: posix
SELECT
  f.directory,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  process_open_sockets pop
  LEFT JOIN processes p0 ON pop.pid = p0.pid
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  (
    p0.name LIKE '.%'
    OR f.filename LIKE '.%'
    OR f.directory LIKE '%/.%'
  )
  AND NOT f.directory LIKE '%/.bin'
  AND NOT f.directory LIKE '%/.bin-unwrapped'
  AND NOT f.directory LIKE '%/.cargo/bin'
  AND NOT f.directory LIKE '%/.fig/bin'
  AND NOT f.directory LIKE '%/.config/nvm/%/bin'
  AND NOT f.directory LIKE '%/.provisio/bin/%'
  AND NOT f.directory LIKE '%/.local/%'
  AND NOT f.directory LIKE '%/node_modules/.bin/%'
  AND NOT f.directory LIKE '%/.nvm/versions/%/bin'
  AND NOT f.directory LIKE '%/.goenv/%/bin'
  AND NOT f.directory LIKE '%/.pnpm/%'
  AND NOT f.directory LIKE '%/.yardstick/%'
  AND NOT f.directory LIKE '%/.go/bin'
  AND NOT f.directory LIKE '%/.rustup/%'
  AND NOT f.directory LIKE '%/.terraform%'
  AND NOT f.directory LIKE '%/.docker/cli-plugins'
  AND NOT f.directory LIKE '%/.cursor/%'
  AND NOT f.directory LIKE '%/.tflint.d/%'
  AND NOT f.directory LIKE '%/.vs-kubernetes/%'
  AND NOT f.directory LIKE '%/.vscode/extensions/%'
  AND NOT f.directory LIKE '%/.vscode-insiders/extensions/%'
  AND NOT f.path LIKE '/home/%/.config/bluejeans-v2/BluejeansHelper'
  AND NOT f.path LIKE '/nix/store/%/%-wrapped'
  AND NOT (
    f.path LIKE '/nix/store/%'
    AND p0.name LIKE '%-wrappe%'
  )
GROUP BY
  f.path
