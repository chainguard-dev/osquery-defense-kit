-- Unexpected process that spawns shell processes (event based)
--
-- false positives:
--   * IDE's
--
-- references:
--   * https://attack.mitre.org/techniques/T1059/ (Command and Scripting Interpreter)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--
-- tags: process events extra
-- interval: 60
-- platform: posix
SELECT
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.start_time AS p0_start,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.start_time AS p1_start,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.start_time AS p2_start,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
  -- Ignore partial table joins
  AND p1_path != ''
  -- Editors & terminals mostly.
  -- I know it's tempting to list "electron" here but please find a more specific exclusion.
  AND p1.name NOT IN (
    'abrt-action-per',
    'abrt-handle-eve',
    'AGSService',
    'alacritty',
    'Alfred',
    'anacron',
    'arduino-cli',
    'auditd',
    'bash',
    'buildkit-runc',
    'build-script-build',
    'chezmoi',
    'clang-11',
    'code',
    'Code Helper (Renderer)',
    'Code - Insiders Helper',
    'Code - Insiders Helper (Renderer)',
    'collect2',
    'com.docker.back',
    'configure',
    'conmon',
    'containerd-shim',
    'Core Sync',
    'Cursor',
    'Cursor Helper',
    'dash',
    'demoit',
    'direnv',
    'dnf',
    'dnf-automatic',
    'doas',
    'Docker Desktop',
    'dumb-init',
    'elastic-security',
    'erl_child_setup',
    'find',
    'FinderSyncExtension',
    'fish',
    'flock',
    'gopls',
    'gdm-wayland-ses',
    'gephi',
    'git',
    'GitKraken Helper (Renderer)',
    'git-remote-http',
    'git-remote-https',
    'gnome-session-b',
    'gnome-shell',
    'go',
    'goland',
    'GoogleSoftwareUpdateAgent',
    'GoogleUpdater',
    'helm',
    'Hyper',
    'i3bar',
    'i3blocks',
    'idea',
    'incusd',
    'inittool2',
    'java',
    'jetbrains_client',
    'just',
    'kitty',
    'ko',
    'konsole',
    'kubectl',
    'kue',
    'ld',
    'lightdm',
    'linux-sandbox',
    'LogiMgrDaemon',
    'LogiTune',
    'logrotate',
    'MacVim',
    'make',
    'Microsoft.VisualStudio.Reliability.Monitor',
    'monorail',
    'newgrp',
    'ninja',
    'nix',
    'nix-build',
    'nix-daemon',
    'node',
    'nu',
    'nvim',
    'OpenLens',
    'package_script_service',
    'pacman',
    'perl',
    'pia-daemon',
    'PK-Backend',
    'provisio',
    'ptyxis-agent',
    'pycharm',
    'qcalc',
    'Rancher Desktop',
    'roxterm',
    'rpmbuild',
    'Runner.Listener',
    'Runner.Worker',
    'screen',
    'sdk',
    'sdzoomplugin',
    'sh',
    'skhd',
    'ssh',
    'sshd',
    'steam_osx',
    'swift',
    'gosec',
    'systemd',
    'terminator',
    'kandji-library-manager',
    'terraform',
    'terraform-provi',
    'test2json',
    'timeout',
    'tmux',
    'tmux:server',
    'udev-worker',
    'unattended-upgr',
    'update-notifier',
    'vi',
    'vim',
    'vim-nox11',
    'VisualStudio',
    'watch',
    'wezterm-gui',
    'xargs',
    'xcrun',
    'xfce4-session',
    'xfce4-terminal',
    'yum',
    'zellij',
    'zsh'
  )
  AND p1_path NOT LIKE '/Applications/%.app/Contents/MacOS/%'
  AND p1_path NOT IN (
    '/Applications/Docker.app/Contents/MacOS/Docker',
    '/Applications/Docker.app/Contents/MacOS/install',
    '/Applications/Hyper.app/Contents/MacOS/Hyper',
    '/usr/bin/make',
    '/Applications/Visual Studio Code.app/Contents/MacOS/Electron',
    '/Applications/Docker.app/Contents/Resources/bin/com.docker.cli',
    '/Applications/Docker.app/Contents/Resources/bin/docker-credential-desktop',
    '/Applications/IntelliJ IDEA.app/Contents/MacOS/idea',
    '/Applications/Alfred 5.app/Contents/Preferences/Alfred Preferences.app/Contents/MacOS/Alfred Preferences',
    '/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service',
    '/Applications/Parallels Desktop.app/Contents/MacOS/prl_update_helper',
    '/Applications/RStudio.app/Contents/Resources/app/bin/rsession-arm64',
    '/Applications/Amazon Photos.app/Contents/MacOS/Amazon Photos',
    '/bin/dash',
    '/usr/bin/less',
    '/usr/bin/networksetup',
    '/bin/sh',
    '/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent',
    '/Library/Application Support/Logitech.localized/LogiOptionsPlus/logioptionsplus_agent.app/Contents/MacOS/logioptionsplus_agent',
    '/Library/Developer/CommandLineTools/usr/bin/git',
    '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateDaemon',
    '/Library/Kandji/Kandji Agent.app/Contents/MacOS/kandji-library-manager',
    '/Library/Kandji/Kandji Agent.app/Contents/Helpers/Kandji Library Manager.app/Contents/MacOS/kandji-library-manager',
    '/opt/X11/libexec/launchd_startx',
    '/Applications/DDPM/DDPM.app/Contents/MacOS/DDPM',
    '/sbin/launchd',
    '/System/Library/Frameworks/Security.framework/authtrampoline',
    '/usr/bin/alacritty',
    '/usr/bin/apt',
    '/usr/sbin/networksetup',
    '/usr/bin/apt-get',
    '/usr/bin/bash',
    '/usr/bin/perl',
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
  AND NOT p0.cmdline IN (
    -- npm run server
    'sh -c -- exec-bin node_modules/.bin/hugo/hugo server',
    'sh -c /usr/bin/defaults write us.zoom.xos NSQuitAlwaysKeepsWindows -bool false',
    '/bin/sh -c ioreg -rd1 -c IOPlatformExpertDevice',
    '/bin/sh -c system_profiler SPDisplaysDataType | grep "Chipset Model"',
    '/usr/bin/python3 /usr/bin/terminator',
    'sh -c echo zoomMute:disabled,zoomVideo:disabled,zoomStatus:closed,zoomShare:disabled,zoomRecord:disabled',
    '/bin/sh -c sysctl hw.model kern.osrelease',
    '/bin/sh /etc/security/audit_warn soft /var/audit',
    'sh -c hugo-installer --version otherDependencies.hugo --extended --destination node_modules/.bin/hugo',
    '/bin/bash -c ioreg -l -w 0 | grep SecureInput',
    "sh -c acpi -b | grep -v 'unavailable'",
    'sh -c xcode-select --print-path >/dev/null 2>&1 && xcrun --sdk macosx --show-sdk-path 2>/dev/null',
    -- Brother printer
    'sh -c ps -xcocommand,pid | grep "LOGINserver"'
  )
  AND NOT (
    p1.name = 'sshd'
    AND p0.cmdline LIKE '%askpass%'
  )
  AND NOT (
    p1.name = '(udev-worker)'
    AND p0.cmdline LIKE '/bin/sh -c echo % > /sys/bus/usb/drivers/brcmfmac/new_id'
  )
  AND NOT (
    p1.name = 'steam'
    AND p0.cmdline LIKE 'sh -c %steamwebhelper.sh%'
  )
  AND NOT (
    p1.name = 'bash'
    AND p0.cmdline LIKE 'sh -s _hostname %'
  )
  AND NOT (
    p1.cmdline LIKE 'perl%/help2man%'
    AND p0.cmdline LIKE 'sh -c man/%'
  )
  AND NOT p0.cmdline LIKE '/bin/sh %/bin/docker-credential-gcloud get'
  AND NOT p1_path LIKE '/private/var/folders/%/T/go-build%.test'
  AND NOT p1_path LIKE '/Users/%/.vscode/extensions/stateful.runme-%/bin/runme'
  AND NOT p1_path LIKE '/private/tmp/PKInstallSandbox.%/tmp/Python/Python3.framework/Versions/%/Resources/Python.app/Contents/MacOS/Python'
  AND NOT p0.cmdline LIKE '%/Library/Apple/System/Library/InstallerSandboxes%'
  AND NOT p0.cmdline LIKE '%gcloud config config-helper%'
  AND NOT p0.cmdline LIKE '%hugo/hugo server%'
  AND NOT p1.cmdline LIKE '%/bin/pytest %'
  AND NOT p0.cmdline LIKE '%/bin/codeclimate %'
  AND NOT p0.cmdline LIKE '%/ChromeRecovery --browser-version=%'
  AND NOT p1.cmdline LIKE '/Applications/Warp.app/%'
  AND NOT p1.cmdline IN ('npm run start', 'npm install')
  AND NOT p1.cmdline LIKE '%brew.rb%'
  AND NOT p1.cmdline LIKE '%/Homebrew/build.rb%'
  AND NOT p1.cmdline LIKE '%Code Helper%'
  AND NOT p1.cmdline LIKE '%Code - Insiders Helper%'
  AND NOT p1.cmdline LIKE '%gcloud.py config config-helper%'
  AND NOT p1.cmdline LIKE '/usr/lib/electron19/electron /usr/lib/code/out/bootstrap-fork --type=ptyHost --logsPath /home/%/.config/Code - OSS/logs/%'
  AND NOT p1.name LIKE '%term%'
  AND NOT p1.name LIKE '%Term%'
  AND NOT p1.name LIKE 'Emacs%'
  AND NOT p1.name LIKE 'terraform-prov%'
  AND NOT p1.path LIKE '/Users/%/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent'
  -- Oh, NixOS.
  AND NOT p1.name LIKE '%/bin/bash'
  AND NOT p1.name LIKE '%/bin/direnv'
  AND NOT p1_path LIKE '/nix/store/%sh'
  AND NOT p1_path LIKE '/opt/homebrew/%'
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p0.cgroup_path LIKE '/system.slice/system.slice:docker:%'
