-- Programs running with a hidden file path or process name
--
-- references:
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- tags: transient
-- platform: posix
SELECT
  f.directory,
  f.btime,
  p0.start_time,
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
  REPLACE(f.directory, u.directory, '~') AS homedir,
  REPLACE(f.path, u.directory, '~') AS homepath,
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
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN users u ON f.uid = u.uid
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
  AND NOT homedir LIKE '%/node_modules/.%'
  -- exclude top-level hidden home directories (there are many)
  AND NOT (
    homedir LIKE '~/.%'
    AND NOT homedir LIKE '~/.config/%'
    AND NOT homedir LIKE '~/.cache/%'
  )
  AND NOT homedir LIKE '~/%/node_modules/.bin%'
  AND NOT homepath LIKE '~/%arm64%'
  AND NOT homepath LIKE '~/%x86_64%'
  AND NOT top2_dir IN (
    '/nix/store/.links',
    '/var~/.local',
    '~/.goenv',
    '~/.vs-kubernetes',
    '~/chainguard-images',
    '~/code',
    '~/Code',
    '~/Projects',
    '~/projects',
    '~/git',
    '~/repos',
    '~/src'
  )
  AND NOT top3_dir IN (
    '/home/linuxbrew/.linuxbrew',
    '/var~/.local/share',
    '~/.cache/gitstatus',
    '~/.cache/cloud-code',
    '~/.cache/go-build',
    '~/.cache/JetBrains',
    '~/.cache/rod',
    '~/.cache/selenium',
    '~/.config/bluejeans-v2',
    '~/.config/Code',
    '~/.config/nvm',
    '~/Documents/GitHub',
    '~/node_modules/.bin',
    '~/thinkorswim/.install4j'
  )
  AND NOT f.directory = '/nix/store/.links'
  AND NOT f.directory LIKE '%/.terraform/%'
  AND NOT f.directory LIKE '%/.zig-cache/%'
  AND NOT f.directory LIKE '%/anchore/grype/.tool%'
  AND NOT f.directory LIKE '%/Applications/PSI Bridge Secure Browser.app/Contents/Resources/.apps/darwin/%'
  AND NOT f.directory LIKE '%/com.jetbrains.GoLand/cache/JetBrains/GoLand%'
  AND NOT f.directory LIKE '/Applications/Corsair iCUE5 Software/.cuepkg-%'
  AND NOT f.directory LIKE '/var/home/linuxbrew/.linuxbrew/Cellar/%'
  AND NOT f.directory LIKE '/var/home/linuxbrew/.linuxbrew/Homebrew/%'
  AND NOT f.directory LIKE '/Volumes/com.getdropbox.dropbox-%'
  AND NOT f.path LIKE '/nix/store/%/%-wrapped'
  AND NOT homepath LIKE '~/.ape-1%'
  AND NOT (
    f.path LIKE '/nix/store/%'
    AND p0.name LIKE '%-wrappe%'
  )
  AND NOT homedir LIKE '%/.Trash/1Password %.app/Contents/Library/LoginItems/1Password Extension Helper.app/Contents/MacOS'
  AND NOT homedir LIKE '%/.Trash/Logi Options.app/Contents/Support/LogiMgrDaemon.app/Contents/MacOS'
  AND NOT homedir LIKE '/Users/%/.Trash/lghub.app/Contents/MacOS/lghub_agent.app/Contents/MacOS'
  AND NOT homedir LIKE '~/%/.venv/bin'
  AND NOT homedir LIKE '~/.local/share/AppImage/ZenBrowser.AppImage'
  AND NOT homedir LIKE '~/.Trash/1Password %.app/Contents/Library/LoginItems/1Password Extension Helper.app/Contents/MacOS'
  AND NOT homedir LIKE '~/Library/Application Support/Code/User/globalStorage/ms-dotnettools.vscode-dotnet-runtime/.dotnet/%'
  AND NOT p0_cgroup LIKE '/system.slice/docker-%'
GROUP BY
  f.path
