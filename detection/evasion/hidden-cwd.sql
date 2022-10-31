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
  hash.sha256,
  REPLACE(p.cwd, u.directory, '~') AS dir,
  CONCAT (
    p.name,
    ',',
    IIF(
      REGEX_MATCH (
        REPLACE(p.cwd, u.directory, '~'),
        '([/~].*?/.*?/.*?)/',
        1
      ) != '',
      REGEX_MATCH (
        REPLACE(p.cwd, u.directory, '~'),
        '([/~].*?/.*?/.*?)/',
        1
      ),
      REPLACE(p.cwd, u.directory, '~')
    )
  ) AS exception_key
FROM
  processes p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  dir LIKE '%/.%'
  AND NOT (
    exception_key IN (
      'bash,~/.local/share',
      'bash,~/go/src',
      'Electron,~/.vscode/extensions',
      'fish,~/.local/share',
      'git,~/.local/share',
      'makepkg,~/.cache/yay',
      'zsh,~/.Trash',
      'bash,~/.Trash',
      'fish,~/.Trash',
      'make,~/.cache/yay',
      'java,~/.gradle/daemon',
      'java,~/.local/share',
      'rust-analyzer-p,~/.cargo/registry',
      'as,~/.cache/yay',
      'c++,~/.cache/yay',
      'cc1plus,~/.cache/yay',
      'npm install,~/.npm/_cacache',
      'mysqld,~/.local/share'
    )
    OR exception_key LIKE '%sh,~/.Trash/%'
    OR dir IN (
      '~/.config',
      '~/.local/bin',
      '~/.vim',
      '~/.terraform.d',
      '~/.cache/yay',
      '~/.local/share/chezmoi',
      '~/.local/share/Steam',
      '~/.local/share/nvim',
      '~/.gmailctl',
      '~/.oh-my-zsh',
      '~/.zsh'
    )
    OR p.name IN (
      'bindfs',
      'vim',
      'nvim',
      'code',
      'updatedb',
      'git',
      'gitsign',
      'Code Helper'
    )
    OR dir LIKE '~/.cache/yay/%'
    OR dir LIKE '~/.cargo/%'
    OR dir LIKE '~/code/%'
    OR dir LIKE '~/.dotfiles/%'
    OR dir LIKE '~/%/.github%'
    OR dir LIKE '~/go/src/%'
    OR dir LIKE '~/.gradle/%'
    OR dir LIKE '/Library/Apple/System/Library/InstallerSandboxes/.PKInstallSandboxManager-SystemSoftware/%'
    OR dir LIKE '~/.local/share/fish/%'
    OR dir LIKE '~/.local/share/JetBrains/%'
    OR dir LIKE '~/.local/share/kotlin/%'
    OR dir LIKE '~/.local/share/nvim/%'
    OR dir LIKE '~/.local/share/Steam/%'
    OR dir LIKE '~/.provisio%'
    OR dir LIKE '~/src/%'
    OR dir LIKE '~/%/.terraform%'
    OR dir LIKE '~/.vscode/extensions/%'
    OR dir LIKE '~/.zsh/%'
    OR dir LIKE '~/%/.git'
    -- For sudo calls to other things
    OR (dir LIKE '/home/.terraform.d/%' AND p.euid = 0)
  )
