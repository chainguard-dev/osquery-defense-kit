-- Suspicious parenting of fetch tools (state-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--
-- tags: transient process state often
-- platform: posix
SELECT
  p.pid,
  p.path,
  p.name AS child_name,
  p.cmdline AS cmd,
  p.cwd,
  p.euid,
  p.parent,
  p.cgroup_path,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  pp.euid AS parent_euid,
  gp.name AS gparent_name,
  gp.cmdline AS gparent_cmd,
  pp.pid AS gparent_pid,
  hash.sha256 AS parent_sha256,
  CONCAT (
    p.name,
    ',',
    MIN(p.euid, 500),
    ',',
    pp.name,
    ',',
    gp.name
  ) AS exception_key
FROM
  processes p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN processes gp ON pp.parent = gp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE -- NOTE: The remainder of this query is synced with unexpected-fetcher-parent-events
  child_name IN ('curl', 'wget', 'ftp', 'tftp') -- And not a regular local user
  AND NOT exception_key IN (
    'curl,0,09-timezone,nm-dispatcher',
    'curl,0,build.sh,buildkit-runc',
    'curl,0,eos-rankmirrors,eos-rankmirrors',
    'curl,0,nm-dispatcher,',
    'curl,0,nm-dispatcher,nm-dispatcher',
    'curl,0,sh,qualys-cloud-ag',
    'curl,0,sh,qualys-scan-uti',
    'curl,300,bash,nix',
    'curl,301,bash,nix',
    'curl,302,bash,nix',
    'curl,303,bash,nix',
    'curl,305,bash,nix',
    'curl,307,bash,nix',
    'curl,500,nwg-panel,systemd',
    'curl,500,bash,bash',
    'curl,500,bash,fakeroot',
    'curl,500,bash,fish',
    'curl,500,bash,nix-daemon',
    'curl,500,bash,ShellLauncher',
    'curl,500,bash,zsh',
    'curl,500,bash,bash',
    'curl,500,env,env',
    'curl,500,zsh,Emacs-arm64-11',
    'curl,500,eos-connection-,eos-update-noti',
    'curl,500,fish,gnome-terminal-',
    'curl,500,launchd,kernel_task',
    'curl,500,makepkg,yay',
    'curl,500,node-cve-count.,bash',
    'curl,500,nvim,nvim',
    'curl,500,ruby,zsh',
    'curl,500,ShellLauncher,',
    'curl,500,ShellLauncher,login',
    'curl,500,Slack,launchd',
    'curl,500,Stats,bash',
    'curl,500,zsh,login',
    'curl,500,zsh,sh',
    'wget,500,env,env',
    'wget,500,sh,bwrap',
    'wget,500,zsh,bash'
  )
  AND NOT (
    p.euid > 500
    AND parent_name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
    AND gparent_name IN (
      'alacritty',
      'gnome-terminal-',
      'kitty',
      'login',
      'roxterm',
      'tmux',
      'stable',
      'old',
      'tmux:server',
      'wezterm-gui',
      'zsh'
    )
  )
  AND NOT p.cmdline IN (
    'curl -s -6 https://api.serhiy.io/v1/stats/ip',
    'curl -s -4 https://api.serhiy.io/v1/stats/ip',
    'curl https://wttr.in/?format=1 -s'
  )
  AND NOT parent_name IN ('yay')
  AND NOT p.cmdline LIKE 'curl -s https://support-sp.apple.com/sp/product%'
  AND NOT (
    p.euid > 500
    AND parent_name = 'env'
    AND parent_cmd LIKE '/usr/bin/env -i % HOMEBREW_BREW_FILE=%'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'ruby'
    AND parent_cmd LIKE '%/Library/Homebrew/brew.rb%'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'env'
    AND parent_cmd LIKE '/usr/bin/env bash ./hack/%.sh'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'bash'
    AND parent_cmd LIKE 'bash ./hack/%.sh'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'bash'
    AND parent_cmd LIKE 'bash %/bin/go-build %'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'ruby'
    AND p.cmdline LIKE '/usr/bin/curl --disable --cookie /dev/null --globoff --show-error --user-agent Homebrew/%'
  )
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p.pid
