-- Find unexpected in unexpected places under /Users
--
-- references:
--   * https://www.elastic.co/security-labs/inital-research-of-jokerspy
--   * https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket
--
-- false positives:
--   * none known
--
-- tags: persistent seldom
-- platform: darwin
SELECT
  f.path,
  f.directory,
  f.uid,
  f.gid,
  f.mode,
  f.mtime,
  f.atime,
  f.btime,
  f.ctime,
  f.size,
  hash.sha256,
  REPLACE(f.directory, u.directory, '~') AS homedir,
  RTRIM(
    COALESCE(
      REGEX_MATCH (
        REPLACE(f.directory, u.directory, '~'),
        '(.*?/.*?/.*?/)',
        1
      ),
      REPLACE(f.directory, u.directory, '~')
    ),
    "/"
  ) AS top2_homedir,
  magic.data,
  signature.authority,
  signature.identifier
FROM
  file f
  LEFT JOIN hash on f.path = hash.path
  LEFT JOIN users u ON f.uid = u.uid
  LEFT JOIN magic ON f.path = magic.path
  LEFT JOIN signature ON f.path = signature.path
WHERE
  -- Optimization: don't join things until we have a whittled down list of files
  f.path IN (
    SELECT DISTINCT
      path
    FROM
      file
    WHERE
      (
        directory = '/Users/Shared/'
        OR directory LIKE '/Users/Shared/%'
        OR directory LIKE '/Users/Shared/.%'
        OR directory LIKE '/Users/%/Library'
        OR directory LIKE '/Users/%/Library/%'
        OR directory LIKE '/Users/%/Library/%/.%'
        OR directory LIKE '/Users/%/Library/%/%'
        OR directory LIKE '/Users/%/Library/.%'
        OR directory LIKE '/Users/%/Public'
        OR directory LIKE '/Users/%/Public/%'
        OR directory LIKE '/Users/%/Public/.%'
        OR directory LIKE '/Users/%/Photos'
        OR directory LIKE '/Users/%/Photos/%'
        OR directory LIKE '/Users/%/Photos/.%'
        OR directory LIKE '/Users/%/.%'
        OR directory LIKE '/Users/%/.%/%'
      )
      AND (
        type = 'regular'
        AND size > 32
        AND (
          mode LIKE '%7%'
          OR mode LIKE '%5%'
          OR mode LIKE '%1%'
        )
      )
      -- Prevent weird recursion
      AND NOT path LIKE '%/../%'
      AND NOT path LIKE '%/./%' -- Exclude very temporary files
      AND NOT directory LIKE '/Users/%/.bin/'
      AND NOT directory LIKE '/Users/%/.cargo/bin/'
      AND NOT directory LIKE '/Users/%/.go/bin/'
      AND NOT directory LIKE '/Users/%/Library/Application Support/AutoFirma/certutil/'
      AND NOT directory LIKE '/Users/%/Library/Caches/chainctl/'
      AND NOT directory LIKE '/Users/%/Library/Containers/%'
      AND NOT directory LIKE '/Users/%/Library/Daemon Containers/%'
      AND NOT directory LIKE '/Users/%/Library/Mobile Documents/com~apple~shoebox/%'
      AND NOT directory LIKE '/Users/%/.local/bin/'
      AND NOT directory LIKE '/Users/%/.minikube/bin/'
      AND NOT directory LIKE '/Users/Shared/LGHUB/depots/%'
      AND NOT directory LIKE '/Users/Shared/LogiOptionsPlus/depots/%'
      AND NOT directory LIKE '/Users/%/.Trash/%'
      AND NOT directory LIKE '/Users/%/.vim/backup/'
      AND NOT directory IN (
        '/Users/Shared/LogiOptionsPlus/cache/',
        '/Users/Shared/logitune/',
        '/Users/Shared/Red Giant/Uninstall/'
      )
      AND NOT (strftime('%s', 'now') - ctime) < 60 -- Only executable files
  )
  AND (
    magic.data IS NULL
    OR magic.data LIKE "%executable%"
    OR magic.data LIKE "%shared library%"
  ) -- Filter out downloaded Linux binaries
  AND NOT (
    magic.data IS NOT NULL
    AND magic.data LIKE "ELF %LSB %"
  )
  AND NOT (
    magic.data IS NOT NULL
    AND magic.data LIKE "0420 Alliant virtual executable%"
  )
  AND NOT (
    magic.data IS NOT NULL
    AND magic.data LIKE "%shell script%"
  )
  AND NOT homedir LIKE '~/%/bin'
  AND NOT homedir LIKE '~/%/shims'
  AND NOT homedir LIKE '~/%/plugins'
  AND NOT homedir IN (
    '~/.bin',
    '~/.fzf',
    '~/.fzf/bin',
    '~/.venv/bin',
    '~/.fig/bin',
    '~/.zsh_snap/zsh-snap',
    '~/.zed/gopls',
    '~/.config/kn',
    '~/.asdf/shims',
    '~/.amplify/bin',
    '~/.emacs.d/backups',
    '~/.rbenv/shims',
    '~/.config/nvim.bak',
    '~/.bazel/bin',
    '~/.pulumi-dev/bin',
    '~/.gvm/bin',
    '~/.emacs.d.bak/bin',
    '~/.docker/cli-plugins',
    '~/.zsh_snap/zsh-autocomplete',
    '~/.cache/gitstatus',
    '~/.wrangler/bin',
    '~/.provisio',
    '~/.pyenv/shims',
    '~/Library/ApplicationSupport/iTerm2',
    '~/.kn/plugins',
    '~/.kuberlr/darwin-amd64',
    '/Users/Shared/logitune',
    '~/.oh-my-zsh/tools',
    '~/Library/Dropbox/DropboxMacUpdate.app/Contents/MacOS'
  )
  AND NOT top2_homedir IN (
    '~/Library/Application Support',
    '/Users/Shared/LGHUB/cache',
    '~/Library/Printers',
    '~/Library/QuickLook',
    '~/Library/pnpm',
    '/Users/Shared/Red Giant/Uninstall',
    '~/Library/Thunderbird',
    '~/Library/helm',
    '~/Library/Services',
    '~/.terraform.d',
    '~/.iterm2',
    '/Users/Shared/LogiOptionsPlus/cache',
    '~/Library/Screen Savers',
    '~/Library/Python',
    '~/Library/Caches',
    '~/.magefile',
    '~/.nvm'
  )
GROUP BY
  f.path
