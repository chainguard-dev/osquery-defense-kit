-- Unexpected process that spawns shell processes (event based)
--
-- false positives:
--   * IDE's
--
-- references:
--   * https://attack.mitre.org/techniques/T1059/ (Command and Scripting Interpreter)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--
-- tags: process events
-- interval: 60
-- platform: posix
SELECT
  p.name,
  p.path AS path,
  p.cmdline AS cmd,
  p.pid,
  p.cgroup_path,
  p.parent,
  p.cwd,
  pp.name AS parent_name,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN processes pp ON pp.pid = p.parent
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  p.name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
  -- Ignore partial table joins
  AND parent_path != ''
  -- Editors & terminals mostly.
  -- I know it's tempting to list "electron" here but please find a more specific exclusion.
  AND pp.name NOT IN (
    'abrt-handle-eve',
    'alacritty',
    'anacron',
    'Alfred',
    'bash',
    'buildkit-runc',
    'build-script-build',
    'chezmoi',
    'clang-11',
    'code',
    'abrt-action-per',
    'Code Helper (Renderer)',
    'Code - Insiders Helper (Renderer)',
    'collect2',
    'configure',
    'conmon',
    'containerd-shim',
    'Core Sync',
    'dash',
    'demoit',
    'direnv',
    'dnf',
    'dnf-automatic',
    'doas',
    'Docker Desktop',
    'dumb-init',
    'erl_child_setup',
    'Runner.Worker',
    'find',
    'FinderSyncExtension',
    'fish',
    'gephi',
    'git',
    'git-remote-https',
    'gnome-session-b',
    'gnome-shell',
    'go',
    'goland',
    'GoogleSoftwareUpdateAgent',
    'helm',
    'i3bar',
    'i3blocks',
    'java',
    'jetbrains_client',
    'kitty',
    'ko',
    'kubectl',
    'kue',
    'lightdm',
    'make',
    'monorail',
    'ninja',
    'nix',
    'nix-build',
    'nix-daemon',
    'node',
    'nvim',
    'package_script_service',
    'pacman',
    'perl',
    'pia-daemon',
    'PK-Backend',
    'provisio',
    'Rancher Desktop',
    'roxterm',
    'rpmbuild',
    'Runner.Listener',
    'Runner.Worker',
    'sdk',
    'sdzoomplugin',
    'sh',
    'skhd',
    'ssh',
    'sshd',
    'steam_osx',
    'LogiTune',
    'inittool2',
    'swift',
    'systemd',
    'terminator',
    'test2json',
    'tmux',
    'tmux:server',
    'update-notifier',
    'vi',
    'vim',
    'watch',
    'wezterm-gui',
    'xargs',
    'xcrun',
    'xfce4-terminal',
    'yum',
    'zellij',
    'zsh'
  )
  AND parent_path NOT IN (
    '/Applications/Docker.app/Contents/MacOS/Docker',
    '/Applications/Docker.app/Contents/MacOS/install',
    '/Applications/Docker.app/Contents/Resources/bin/com.docker.cli',
    '/Applications/Docker.app/Contents/Resources/bin/docker-credential-desktop',
    '/Applications/IntelliJ IDEA.app/Contents/MacOS/idea',
    '/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service',
    '/Applications/Parallels Desktop.app/Contents/MacOS/prl_update_helper',
    '/Applications/RStudio.app/Contents/Resources/app/bin/rsession-arm64',
    '/bin/dash',
    '/bin/sh',
    '/Library/Application Support/Logitech.localized/LogiOptionsPlus/logioptionsplus_agent.app/Contents/MacOS/logioptionsplus_agent',
    '/Library/Developer/CommandLineTools/usr/bin/git',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateDaemon',
    '/Library/Kandji/Kandji Agent.app/Contents/MacOS/kandji-library-manager',
    '/opt/X11/libexec/launchd_startx',
    '/sbin/launchd',
    '/System/Library/Frameworks/Security.framework/authtrampoline',
    '/usr/bin/alacritty',
    '/usr/bin/apt',
    '/usr/bin/apt-get',
    '/usr/bin/bash',
    '/usr/bin/bwrap',
    '/usr/bin/crond',
    '/usr/bin/dash',
    '/usr/bin/dirname',
    '/usr/bin/login',
    '/usr/bin/man',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/bin/sysdiagnose',
    '/usr/bin/xargs',
    '/usr/bin/zsh',
    '/usr/libexec/gdm-x-session',
    '/usr/libexec/gnome-terminal-server',
    '/usr/libexec/periodic-wrapper',
    '/usr/lib/xorg/Xorg'
  )
  AND NOT p.cmdline IN (
    -- npm run server
    'sh -c -- exec-bin node_modules/.bin/hugo/hugo server',
    '/bin/sh -c ioreg -rd1 -c IOPlatformExpertDevice',
    "sh -c acpi -b | grep -v 'unavailable'",
    'sh -c xcode-select --print-path >/dev/null 2>&1 && xcrun --sdk macosx --show-sdk-path 2>/dev/null',
    -- Brother printer
    'sh -c ps -xcocommand,pid | grep "LOGINserver"'
  )
  AND NOT (
    pp.name = 'sshd'
    AND p.cmdline LIKE '%askpass%'
  )
  AND NOT (
    pp.name = 'steam'
    AND p.cmdline LIKE 'sh -c %steamwebhelper.sh%'
  )
  AND NOT (
    pp.name = 'bash'
    AND p.cmdline LIKE 'sh -s _hostname %'
  )
  AND NOT (
    pp.cmdline LIKE 'perl%/help2man%'
    AND p.cmdline LIKE 'sh -c man/%'
  )
  AND NOT p.cmdline LIKE '/bin/sh %/bin/docker-credential-gcloud get'
  AND NOT parent_path LIKE '/private/var/folders/%/T/go-build%.test'
  AND NOT p.cmdline LIKE '%/Library/Apple/System/Library/InstallerSandboxes%'
  AND NOT p.cmdline LIKE '%gcloud config config-helper%'
  AND NOT p.cmdline LIKE '%hugo/hugo server%'
  AND NOT pp.cmdline LIKE '/Applications/Warp.app/%'
  AND NOT pp.cmdline = 'npm run start'
  AND NOT pp.cmdline LIKE '%brew.rb%'
  AND NOT pp.cmdline LIKE '%/Homebrew/build.rb%'
  AND NOT pp.cmdline LIKE '%Code Helper%'
  AND NOT pp.cmdline LIKE '%gcloud.py config config-helper%'
  AND NOT pp.cmdline LIKE '/usr/lib/electron19/electron /usr/lib/code/out/bootstrap-fork --type=ptyHost --logsPath /home/%/.config/Code - OSS/logs/%'
  AND NOT pp.name LIKE '%term%'
  AND NOT pp.name LIKE '%Term%'
  AND NOT pp.name LIKE 'Emacs%'
  AND NOT pp.name LIKE 'terraform-provider-%'
  AND NOT pp.path LIKE '/Users/%/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent'
  -- Oh, NixOS.
  AND NOT pp.name LIKE '%/bin/bash'
  AND NOT pp.name LIKE '%/bin/direnv'
  AND NOT parent_path LIKE '/nix/store/%sh'
  AND NOT parent_path LIKE '/opt/homebrew/%'
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p.cgroup_path LIKE '/system.slice/system.slice:docker:%'
