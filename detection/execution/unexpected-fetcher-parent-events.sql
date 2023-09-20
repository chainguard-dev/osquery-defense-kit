-- Suspicious parenting of fetch tools (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--
-- tags: transient process state often
-- platform: posix
-- interval: 450
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.time AS p0_time,
  pe.euid AS p0_euid,
  p.cgroup_path AS p0_cgroup,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS exception_key
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  -- NOTE: The remainder of this query is synced with unexpected-fetcher-parents
  pe.cmdline != ''
  AND pe.time > (strftime('%s', 'now') -450)
  AND p0_name IN ('curl', 'wget', 'ftp', 'tftp')
  AND NOT exception_key IN (
    'curl,0,nm-dispatcher,',
    'curl,500,bash,bash',
    'curl,0,nm-dispatcher,nm-dispatcher',
    'curl,500,bash,nix-daemon',
    'curl,500,bash,ShellLauncher',
    'curl,500,bash,zsh',
    'curl,500,env,env',
    'curl,500,fish,gnome-terminal-',
    'curl,500,bash,yay',
    'curl,500,ruby,zsh',
    'curl,500,ShellLauncher,',
    'curl,500,ShellLauncher,login',
    'curl,500,zsh,login',
    'curl,500,zsh,sh',
    'wget,500,env,env'
  )
  AND NOT (
    pe.euid > 500
    AND p1_name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
    AND p2_name IN (
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
  AND NOT p1_name IN ('yay', 'nvim')
  AND NOT (
    pe.euid > 500
    AND p0_cmd IN ('curl --fail https://ipinfo.io/timezone')
  )
  AND NOT (
    pe.euid > 500
    AND p1_name = 'env'
    AND p1_cmd LIKE '/usr/bin/env -i % HOMEBREW_BREW_FILE=%'
  )
  AND NOT (
    pe.euid > 500
    AND p1_name = 'ruby'
    AND p1_cmd LIKE '%/Homebrew/brew.rb%'
  )
  AND NOT (
    pe.euid > 500
    AND p1_name = 'env'
    AND p1_cmd LIKE '/usr/bin/env bash ./hack/%.sh'
  )
  AND NOT p0_cmd LIKE 'wget --no-check-certificate https://github.com/istio/istio/%'
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  pe.pid
