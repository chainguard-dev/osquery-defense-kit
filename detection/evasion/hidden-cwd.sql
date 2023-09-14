-- Programs running with a hidden current working directory (state-based)
--
-- false positives:
--   * Users rummaging through their configuration files
--
-- references:
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- tags: transient often
-- platform: posix
SELECT
  REPLACE(p0.cwd, u.directory, '~') AS dir,
  REGEX_MATCH (
    REPLACE(p0.cwd, u.directory, '~'),
    '([/~].*?/.*?)/',
    1
  ) AS top_dir,
  CONCAT (
    p0.name,
    ',',
    IIF(
      REGEX_MATCH (
        REPLACE(p0.cwd, u.directory, '~'),
        '([/~].*?/.*?/.*?)/',
        1
      ) != '',
      REGEX_MATCH (
        REPLACE(p0.cwd, u.directory, '~'),
        '([/~].*?/.*?/.*?)/',
        1
      ),
      REPLACE(p0.cwd, u.directory, '~')
    )
  ) AS exception_key,
  -- Child
  p0.pid AS p0_pid,
  p0.cgroup_path AS p0_cgroup,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.cgroup_path AS p1_cgroup,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
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
  LEFT JOIN users u ON p0.uid = u.uid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT DISTINCT
      pid
    FROM
      processes
    WHERE
      cwd LIKE '%/.%'
      AND NOT name IN (
        'bindfs',
        'vim',
        'find',
        'nvim',
        'terraform',
        'code',
        'updatedb',
        'git',
        'gitsign',
        'Code Helper'
      )
      AND NOT cgroup_path LIKE '/system.slice/docker-%'
      AND NOT cgroup_path LIKE '/system.slice/system.slice:docker:%'
  )
  AND NOT (
    exception_key IN (
      'as,~/.cache/yay',
      'bash,~/go/src',
      'bash,~/.local/share',
      'bash,~/.Trash',
      'cc1,/home/build/.cache',
      'cc1plus,~/.cache/yay',
      'c++,~/.cache/yay',
      'cgo,~/.gimme/versions',
      'dirhelper,/private/var/folders',
      'Electron,~/.vscode/extensions',
      'fish,~/.local/share',
      'rustc,/home/build/.cargo',
      'fish,~/.Trash',
      'git,~/.local/share',
      'java,/home/build/.gradle',
      'java,~/.gradle/daemon',
      'java,/home/build/.kotlin',
      'java,~/.local/share',
      'make,~/.cache/yay',
      'makepkg,~/.cache/yay',
      'mysqld,~/.local/share',
      'npm install,~/.npm/_cacache',
      'opera_autoupdate,/private/var/folders',
      'rust-analyzer-p,~/.cargo/registry',
      'vet,/home/build/.cache',
      'zsh,~/.Trash'
    )
    OR exception_key LIKE '%sh,~/.Trash/%'
    OR exception_key LIKE '%sh,~/dev/%'
    OR exception_key LIKE 'wineserver,/tmp/.wine-1000/server-%'
    OR exception_key LIKE 'java,/.gradle/%'
    OR dir IN (
      '~/.config',
      '~/.local/bin',
      '~/.vim',
      '~/.provisio',
      '~/.terraform.d',
      '~/.cache/yay',
      '~/.emacs.d',
      '~/.local/share/chezmoi',
      '~/.local/share/Steam',
      '~/.local/share/nvim',
      '~/.gmailctl',
      '~/.oh-my-zsh',
      '~/.hunter/_Base',
      '~/.zsh'
    )
    OR top_dir IN ('~/Sync')
    OR dir LIKE '/Library/Apple/System/Library/InstallerSandboxes/.PKInstallSandboxManager-SystemSoftware/%'
    OR dir LIKE '/opt/homebrew/%/.cache/%'
    OR dir LIKE '/private/tmp/%/.git'
    OR dir LIKE '/tmp/.mount_%'
    OR dir LIKE '/tmp/%/.git'
    OR dir LIKE '~/%/.tests/%'
    OR dir LIKE '/tmp/%/.github/workflows'
    OR dir LIKE '~/%/.terragrunt-cache/%'
    OR dir LIKE '%/.build'
    OR dir LIKE '%/.git'
    OR dir LIKE '%/.gradle'
    OR dir LIKE '%/.github/%'
    OR dir LIKE '%/.github'
    OR dir LIKE '%/.venv'
    OR dir LIKE '/home/build/.cache%'
    OR dir LIKE '~/.%'
    OR dir LIKE '~/.gradle/%'
    OR dir LIKE '~/%/.config/nvim'
    OR dir LIKE '~/%/.docker%'
    OR dir LIKE '/.gradle/%'
    OR dir LIKE '~/%/.modcache/%'
    OR dir LIKE '~/%/.terraform%'
    OR dir LIKE '~/%/.vercel%'
    OR dir LIKE '~/%/github.com/%'
    OR dir LIKE '~/%/node_modules/.pnpm/%'
    OR dir LIKE '~/%/src/%'
    OR dir LIKE '~/%google-cloud-sdk/.install/.backup%'
    OR dir LIKE '~/code/%'
    OR dir LIKE '~/dev/%/dots/%/.config%'
    OR dir LIKE '~/src/%'
    -- For sudo calls to other things
    OR (
      dir LIKE '/home/.terraform.d/%'
      AND p0.euid = 0
    )
  )
GROUP BY
  p0.pid
