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
  REPLACE(f.path, u.directory, '~') AS homepath,
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
        OR directory = '/var/root/'
        OR directory LIKE '/Users/%/.%'
        OR directory LIKE '/Users/%/.%/%'
        OR directory LIKE '/Users/%/Library'
        OR directory LIKE '/Users/%/Library/.%'
        OR directory LIKE '/Users/%/Library/%'
        OR directory LIKE '/Users/%/Library/%/.%'
        OR directory LIKE '/Users/%/Photos'
        OR directory LIKE '/Users/%/Photos/.%'
        OR directory LIKE '/Users/%/Photos/%'
        OR directory LIKE '/Users/%/Public'
        OR directory LIKE '/Users/%/Public/.%'
        OR directory LIKE '/Users/%/Public/%'
        OR directory LIKE '/Users/Shared/.%'
        OR directory LIKE '/Users/Shared/%'
        OR directory LIKE '/var/root/.%'
        OR directory LIKE '/var/root/%'
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
      AND NOT directory LIKE '/Users/%/.crc/bin/'
      AND NOT directory LIKE '/Users/%/.go/bin/'
      AND NOT directory LIKE '/Users/%/.venv/bin/'
      AND NOT directory LIKE '/Users/%/.local/bin/'
      AND NOT directory LIKE '/Users/%/.minikube/bin/'
      AND NOT directory LIKE '/Users/%/.Trash/%'
      AND NOT directory LIKE '/Users/%/.vim/backup/'
      AND NOT directory LIKE '/Users/%/Library/Application Support/AutoFirma/certutil/'
      AND NOT directory LIKE '/Users/%/Library/Caches/chainctl/'
      AND NOT directory LIKE '/Users/%/Library/Containers/%'
      AND NOT directory LIKE '/Users/%/Library/Daemon Containers/%'
      AND NOT directory LIKE '/Users/%/Library/Mobile Documents/com~apple~CloudDocs/'
      AND NOT directory LIKE '/Users/%/Library/Mobile Documents/com~apple~shoebox/%'
      AND NOT directory LIKE '/Users/Shared/LGHUB/%'
      AND NOT directory LIKE '/Users/Shared/LogiOptionsPlus/%'
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
  AND NOT (
    magic.data IS NULL
    AND f.size < 50000
  )
  AND NOT homedir LIKE '/Users/%/.provisio'
  AND NOT homedir LIKE '~/%/bin'
  AND NOT homedir LIKE '~/%/plugins'
  AND NOT homedir LIKE '~/%/shims'
  AND NOT homedir IN (
    '/Users/Shared/LGHUB',
    '/Users/Shared/LogiOptionsPlus',
    '/Users/Shared/logitune',
    '/var/root/.PenTablet',
    '~/.amplify/bin',
    '~/.asdf/shims',
    '~/.bazel/bin',
    '~/.bin',
    '~/.cache/gitstatus',
    '~/.config/kn',
    '~/.config/nvim.bak',
    '~/.docker/cli-plugins',
    '~/.docker/scout',
    '~/.dotnet/tools',
    '~/.emacs.d.bak/bin',
    '~/.oh-my-zsh/themes',
    '~/.emacs.d/backups',
    '~/.fig/bin',
    '~/.fzf',
    '~/.fzf/bin',
    '~/.gvm/bin',
    '~/.kn/plugins',
    '~/.kuberlr/darwin-amd64',
    '~/.npm/sentry-cli',
    '~/.oh-my-zsh/tools',
    '~/.PenTablet',
    '~/.provisio',
    '~/.pulumi-dev/bin',
    '~/.pyenv/shims',
    '~/.rbenv/shims',
    '~/.venv/bin',
    '~/.vs-tekton',
    '~/.wash/downloads',
    '~/.wrangler/bin',
    '~/.zed/gopls',
    '~/.zsh_snap/zsh-autocomplete',
    '~/.zsh_snap/zsh-snap',
    '~/Library/ApplicationSupport/iTerm2',
    '~/Library/Dropbox/DropboxMacUpdate.app/Contents/MacOS',
    '~/Library/Group Containers/group.com.apple.wifi.logs/previous',
    '~/Library/Logs/Adobe',
    '~/Library/Logs/com.logmein.GoToOpener',
    '~/Library/Mobile Documents/com~apple~CloudDocs'
  )
  AND NOT top2_homedir IN (
    '/Users/Shared/LGHUB/cache',
    '/Users/Shared/LogiOptionsPlus/cache',
    '/Users/Shared/Red Giant/Uninstall',
    '~/.antigen',
    '~/.cache/fsh',
    '~/.docker.old/cli-plugins',
    '~/.fzf/test',
    '~/.iterm2',
    '~/.kuberlr/darwin-arm64',
    '~/.claude-code-tools',
    '~/.magefile',
    '~/.nvm',
    '~/.revox/updates',
    '~/.sdkman/libexec',
    '~/.terraform.d',
    '~/.wakatime',
    '~/.terraform.versions',
    '~/Library/Application Support',
    '~/Library/Caches',
    '~/Library/CloudStorage',
    '~/Library/helm',
    '~/Library/pnpm',
    '~/Library/Printers',
    '~/Library/Python',
    '~/Library/QuickLook',
    '~/Library/Screen Savers',
    '~/Library/Services',
    '~/Library/Thunderbird'
  )
  AND NOT homepath IN (
    '~/.config/i3',
    '~/.config/nvm/nvm.sh',
    '~/.config/polybar',
    '~/.config/i3/power-manager.sh',
    '~/.config/polybar/launch.sh',
    '~/.toolbase/toolbase-runner',
    '~/Library/Group Containers/group.com.docker/unleash-repo-schema-v1-Docker Desktop.json',
    '~/Library/Preferences/Macromedia/Flash Player/www.macromedia.com/bin/airappinstaller/airappinstaller_rsrc',
    '~/Library/Keychains/login.keychain-db',
    '~/Library/Logs/zoom.us/upload_history.txt',
    '~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'
  )
  AND NOT top2_homedir LIKE '~/.mvnGoLang/go%.darwin-amd64'
  AND NOT homepath LIKE '~/Library/%/%.db-wal'
  AND NOT homepath LIKE '~/Library/%/%.db'
  AND NOT homepath LIKE '~/Library/%/%.sqlite%'
  AND NOT homepath LIKE '~/Library/%.aapbz'
  AND NOT f.directory LIKE '/Users/%/.docker/cli-plugins'
  AND NOT f.directory LIKE '/Users/%/.nix-profile/%'
  AND NOT f.directory LIKE '/Users/%/.pkg-cache/%'
  AND NOT f.directory LIKE '/Users/%/.npm-global/bin'

  AND NOT f.directory LIKE '/var/root/Library/Caches/%/org.sparkle-project.Sparkle/%/Contents/MacOS'
  AND NOT f.directory LIKE '/var/root/Library/Caches/%/org.sparkle-project.Sparkle/%/Sparkle.framework%'
  AND NOT f.path LIKE '/Users/%/Library/Fonts/%.otf'
  AND NOT f.path LIKE '/Users/%/Library/Fonts/%.ttf'
  AND NOT f.path LIKE '/Users/%/result/activate'
GROUP BY
  f.path
