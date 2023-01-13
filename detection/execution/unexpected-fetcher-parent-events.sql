-- Suspicious parenting of fetch tools (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--
-- tags: transient process state often
-- platform: posix
-- interval: 900
SELECT
  pe.path AS child_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS child_name,
  TRIM(pe.cmdline) AS child_cmd,
  pe.pid AS child_pid,
  p.cgroup_path AS child_cgroup,
  pe.parent AS parent_pid,
  TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
  TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
  IIF(pp.path != NULL, phash.sha256, pehash.sha256) AS parent_hash,
  REGEX_MATCH (
    IIF(pp.path != NULL, pp.path, ppe.path),
    '.*/(.*)',
    1
  ) AS parent_name,
  TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
  TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
  IIF(gp.path != NULL, gphash.sha256, gpehash.path) AS gparent_hash,
  REGEX_MATCH (
    IIF(gp.path != NULL, gp.path, gpe.path),
    '.*/(.*)',
    1
  ) AS gparent_name,
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid,
  CONCAT (
    REGEX_MATCH (pe.path, '.*/(.*)', 1),
    ',',
    MIN(pe.euid, 500),
    ',',
    REGEX_MATCH (
      IIF(pp.path != NULL, pp.path, ppe.path),
      '.*/(.*)',
      1
    ),
    ',',
    REGEX_MATCH (
      IIF(gp.path != NULL, gp.path, gpe.path),
      '.*/(.*)',
      1
    )
  ) AS exception_key
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN hash phash ON pp.path = phash.path
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN hash pehash ON ppe.path = pehash.path
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN hash gphash ON gp.path = gphash.path
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash gpehash ON gpe.path = gpehash.path
WHERE
  -- NOTE: The remainder of this query is synced with unexpected-fetcher-parents
  child_name IN ('curl', 'wget', 'ftp', 'tftp')
  AND pe.time > (strftime('%s', 'now') -900) -- Ignore partial table joins
  AND NOT exception_key IN (
    'curl,0,nm-dispatcher,',
    'curl,0,nm-dispatcher,nm-dispatcher',
    'curl,500,bash,nix-daemon',
    'curl,500,bash,ShellLauncher',
    'curl,500,bash,zsh',
    'curl,500,env,env',
    'curl,500,fish,gnome-terminal-',
    'curl,500,ruby,zsh',
    'curl,500,ShellLauncher,',
    'curl,500,ShellLauncher,login',
    'curl,500,zsh,login',
    'curl,500,zsh,sh',
    'wget,500,env,env'
  )
  AND NOT (
    pe.euid > 500
    AND parent_name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
    AND gparent_name IN (
      'alacritty',
      'gnome-terminal-',
      'kitty',
      'login',
      'roxterm',
      'tmux',
      'tmux:server',
      'wezterm-gui',
      'zsh'
    )
  )
  AND NOT parent_name IN ('yay', 'nvim')
  AND NOT (
    pe.euid > 500
    AND child_cmd IN ('curl --fail https://ipinfo.io/timezone')
  )
  AND NOT (
    pe.euid > 500
    AND parent_name = 'env'
    AND parent_cmd LIKE '/usr/bin/env -i % HOMEBREW_BREW_FILE=%'
  )
  AND NOT (
    pe.euid > 500
    AND parent_name = 'ruby'
    AND parent_cmd LIKE '%/opt/homebrew/Library/Homebrew/brew.rb%'
  )
  AND NOT (
    pe.euid > 500
    AND parent_name = 'env'
    AND parent_cmd LIKE '/usr/bin/env bash ./hack/%.sh'
  )
  AND NOT child_cmd LIKE 'wget --no-check-certificate https://github.com/istio/istio/%'
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  pe.pid
