-- Programs running with a hidden file path or process name
--
-- references:
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- tags: transient
-- platform: posix
SELECT f.directory,
  f.btime,
  p0.start_time,
  REPLACE(f.directory, u.directory, '~') AS dir,
  RTRIM(
    COALESCE(
      REGEX_MATCH (
        REPLACE(f.directory, u.directory, '~'),
        '([/~].*?/.*?)/',
        1
      ),
      f.directory
    ),
    "/"
  ) AS top2_dir,
  COALESCE(
    REGEX_MATCH (
      REPLACE(f.directory, u.directory, '~'),
      '([/~].*?/.*?/.*?)/',
      1
    ),
    REPLACE(f.directory, u.directory, '~')
  ) AS top3_dir,
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
FROM processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN users u ON f.uid = u.uid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE (
    p0.name LIKE '.%'
    OR f.filename LIKE '.%'
    OR f.directory LIKE '%/.%'
  )
  AND NOT top2_dir IN (
    '~/.dropbox-dist',
    '~/.goenv',
    '~/.gradle/jdks',
    '~/.local',
    '~/.pnpm',
    '~/.rbenv',
    '~/.rustup',
    '~/.sdkman',
    '~/.supermaven',
    '~/.terraform',
    '~/.tflint.d',
    '~/.vs-kubernetes'
  )
  AND NOT top3_dir IN (
    '~/.bin',
    '~/.bin-unwrapped',
    '~/.cache/selenium/chromedriver/~',
    '~/.cargo/bin',
    '~/.config/bluejeans-v2',
    '~/.config/Code',
    '~/.config/nvm',
    '~/.arkade/bin',
    '~/.cache/gitstatus',
    '~/.cursor',
    '~/.deno/bin',
    '~/.devpod/contexts',
    '~/.docker/cli-plugins',
    '~/.fig/bin',
    '~/.go/bin',
    '~/.linkerd2/bin',
    '~/.linuxbrew/Cellar',
    '~/node_modules/.bin',
    '~/.nvm/versions',
    '~/.provisio/bin',
    '~/.pyenv/versions',
    '~/.steampipe/db',
    '~/thinkorswim/.install4j',
    '~/.vscode/extensions',
    '~/.vscode-insiders/extensions'
  )
  AND NOT dir LIKE '~/Library/Application Support/Code/User/globalStorage/ms-dotnettools.vscode-dotnet-runtime/.dotnet/%'
  AND NOT dir LIKE '%/.terraform/providers/%'
  AND NOT f.directory LIKE '/Applications/Corsair iCUE5 Software/.cuepkg-%'
  AND NOT f.directory LIKE '%/Applications/PSI Bridge Secure Browser.app/Contents/Resources/.apps/darwin/%'
  AND NOT f.directory LIKE '/var/home/linuxbrew/.linuxbrew/Cellar/%'
  AND NOT f.path LIKE '/nix/store/%/%-wrapped'
  AND NOT (
    f.path LIKE '/nix/store/%'
    AND p0.name LIKE '%-wrappe%'
  )
  AND NOT f.path LIKE '/private/var/root/.Trash/OneDrive %.app/Contents/StandaloneUpdater.app/Contents/MacOS'
GROUP BY f.path