-- Suspicious parenting of fetch tools (state-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--
-- tags: transient process state often
-- platform: posix
SELECT p.pid,
  p.path,
  p.name AS child_name,
  p.cmdline,
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
  CONCAT(
    p.name,
    ',',
    MIN(p.euid, 500),
    ',',
    pp.name,
    ',',
    gp.name
  ) AS exception_key
FROM processes p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN processes gp ON pp.parent = gp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE child_name IN ('curl', 'wget', 'ftp', 'tftp') -- And not a regular local user
  AND NOT (
    p.euid > 500
    AND parent_name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
    AND gparent_name IN (
      'alacritty',
      'gnome-terminal-',
      'roxterm',
      'tmux',
      'tmux:server',
      'wezterm-gui',
      'kitty',
      'zsh'
    )
  )
  AND NOT parent_name IN ('yay')
  AND NOT exception_key IN (
    'curl,500,fish,gnome-terminal-',
    'curl,500,bash,zsh'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'env'
    AND parent_cmd LIKE '/usr/bin/env -i % HOMEBREW_BREW_FILE=%'
  )
  AND NOT (
    p.euid > 500
    AND parent_name = 'ruby'
    AND parent_cmd LIKE '%/opt/homebrew/Library/Homebrew/brew.rb%'
  )
GROUP BY p.pid