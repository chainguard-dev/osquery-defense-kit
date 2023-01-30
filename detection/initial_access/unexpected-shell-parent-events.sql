-- Unexpected process that spawns shell processes (event-based)
--
-- false positives:
--   * IDE's
--
-- references:
--   * https://attack.mitre.org/techniques/T1059/ (Command and Scripting Interpreter)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--
-- tags: process events
-- interval: 300
-- platform: posix
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.pid AS p0_pid,
  p.cgroup_path AS p0_cgroup,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH(COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(p1_p2_hash.path, pe1_p2_hash.path, pe1_pe2_hash.path) AS p2_hash,
  REGEX_MATCH(COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path), '.*/(.*)', 1) AS p2_name,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH(COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH(COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path), '.*/(.*)', 1) AS exception_key
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path

  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  pe.time > (strftime('%s', 'now') -300)
  AND pe.cmdline != ''
  AND pe.parent > 0
  AND p0_name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
  AND NOT (
    p1_name IN (
      'abrt-handle-eve',
      'alacritty',
      'at-spi-bus-launcher',
      'bash',
      'build-script-build',
      'chainctl',
      'chezmoi',
      'clang-11',
      'code',
      'Code Helper (Renderer)',
      'Code - Insiders Helper (Renderer)',
      'collect2',
      'com.docker.backend',
      'conmon',
      'containerd-shim',
      'cpptools',
      'dash',
      'demoit',
      'direnv',
      'doas',
      'docker-credential-desktop',
      'docker-credential-gcr',
      'Docker Desktop',
      'Emacs-arm64-11',
      'env',
      'erl_child_setup',
      'find',
      'FinderSyncExtension',
      'fish',
      'gatherheaderdoc',
      'gdm3',
      'gdm-session-worker',
      'gdm-x-session',
      'git',
      'gke-gcloud-auth-plugin',
      'gnome-session-binary',
      'gnome-shell',
      'gnome-terminal-server',
      'go',
      'goland',
      'gopls',
      'helm',
      'HP Diagnose & Fix',
      'i3bar',
      'i3blocks',
      'java',
      'kitty',
      'ko',
      'kubectl',
      'lightdm',
      'local-path-provisioner',
      'login',
      'make',
      'monorail',
      'my_print_defaults',
      'ninja',
      'nix',
      'nix-build',
      'nix-daemon',
      'nm-dispatcher',
      'node',
      'nvim',
      'package_script_service',
      'perl',
      'PK-Backend',
      'pulumi',
      -- 'python' - do not include this, or you won't detect supply-chain attacks.
      'roxterm',
      'sdk',
      'sdzoomplugin',
      'sh',
      'ShellLauncher',
      'skhd',
      'snyk',
      'sshd',
      'Stream Deck',
      'sudo',
      'swift',
      'systemd',
      'systemd-sleep',
      'terminator',
      'terraform-ls',
      'test2json',
      'tmux',
      'tmux:server',
      'update-notifier',
      'vi',
      'vim',
      'Vim',
      'watch',
      'wezterm-gui',
      'xargs',
      'xcrun',
      'xfce4-terminal',
      'Xorg',
      'yay',
      'yum',
      'zed',
      'zellij',
      'zsh'
    )
    OR p1_name LIKE 'terraform-provider-%'
    -- Do not add shells to this list if you want your query to detect
    -- bad programs that were started from a shell.
    OR p2_name IN ('env', 'git')
    -- Homebrew, except we don't want to allow all of ruby
    OR p0_cmd IN (
      '/bin/bash /usr/bin/xdg-settings set default-url-scheme-handler slack Slack.desktop',
      '/bin/sh -c lsb_release -a --short',
      '/bin/sh -c ps ax -ww -o pid,ppid,uid,gid,args',
      '/bin/sh /usr/bin/lsb_release -a --short',
      '/bin/zsh -c ls',
      'sh -c /bin/stty size 2>/dev/null',
      "sh -c osascript -e 'user locale of (get system info)'",
      'sh -c python3.7 --version 2>&1',
      'sh -c xcode-select --print-path >/dev/null 2>&1 && xcrun --sdk macosx --show-sdk-path 2>/dev/null'
    )
    OR (
      p1_name = 'WhatsApp'
      -- WhatsApp grabs the serial number from people's machines :(
      AND p0_cmd = '/bin/sh -c ioreg -c IOPlatformExpertDevice -d 2'
    )
    OR p1_cmd IN (
      '/usr/bin/python3 /usr/share/apport/apport-gtk',
      'php ./autodocs update images'
    )
    OR (
      p1_cmd LIKE '%Python% /opt/homebrew/bin/jupyter%'
      AND p0_cmd = '/bin/sh -c osascript'
    )
    OR (
      p1_name = 'osqueryd'
      AND p0_cmd LIKE '/bin/sh /etc/NetworkManager/dispatcher.d/%'
    )
    OR (
      p1_name = 'ssh'
      AND p0_cmd LIKE 'gcloud.py compute start-iap-tunnel%'
    )

    OR exception_key IN (
      'bash,0,pia-daemon,launchd',
      'zsh,500,python3.10,gnome-shell'
    )
    OR p0_cmd LIKE '%/bash -e%/bin/as -arch%'
    OR p0_cmd LIKE '/bin/bash /usr/local/Homebrew/%'
    OR p0_cmd LIKE '/bin/bash /opt/homebrew/%'
    OR p0_cmd LIKE '/bin/sh -c pkg-config %'
    OR p0_cmd LIKE '/bin/sh %/docker-credential-gcloud get'
    OR p0_cmd LIKE '%/google-chrome% --flag-switches-begin % --product-version'
    OR p0_cmd LIKE '/bin/sh /usr/bin/xdg-open %'
    OR p0_cmd LIKE '/bin/bash /usr/bin/xdg-settings check %'
    OR p0_cmd LIKE '/bin/sh /usr/bin/xdg-settings set %'
    OR p0_cmd LIKE '/bin/sh /usr/bin/xdg-settings check %'
    OR p0_cmd LIKE '%gcloud config config-helper --format=json'
    OR p0_cmd LIKE '%gcloud config get-value%'
    OR p1_cmd LIKE '%Python /opt/homebrew/bin/aws configure sso'
    OR p2_cmd LIKE '/bin/bash /usr/local/bin/brew%'
    OR p2_cmd LIKE '/usr/bin/python3 -m py_compile %'
  )
GROUP BY
  pe.pid
