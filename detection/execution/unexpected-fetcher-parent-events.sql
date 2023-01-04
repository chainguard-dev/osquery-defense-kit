-- Suspicious parenting of fetch tools (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--
-- tags: transient process state often
-- platform: posix
-- interval: 900
SELECT pe.path AS child_path,
    REGEX_MATCH (pe.path, '.*/(.*)', 1) AS child_name,
    TRIM(pe.cmdline) AS child_cmd,
    pe.pid AS child_pid,
    p.cgroup_path AS child_cgroup,
    p.parent AS parent_pid,
    TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
    TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
    REGEX_MATCH (
        IIF(pp.path != NULL, pp.path, ppe.path),
        '.*/(.*)',
        1
    ) AS parent_name,
    TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
    TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
    REGEX_MATCH (
        IIF(gp.path != NULL, gp.path, gpe.path),
        '.*/(.*)',
        1
    ) AS gparent_name,
    IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid,
    CONCAT(
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
FROM process_events pe
    LEFT JOIN processes p ON pe.pid = p.pid
    LEFT JOIN processes pp ON pe.parent = pp.pid
    LEFT JOIN process_events ppe ON pe.parent = ppe.pid
    LEFT JOIN processes gp ON gp.pid = pp.parent
    LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
WHERE child_name IN ('curl', 'wget', 'ftp', 'tftp')
    AND pe.time > (strftime('%s', 'now') -900) -- Ignore partial table joins
    AND NOT (
        pe.euid > 500
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
        pe.euid > 500 AND
        parent_name = 'env' AND
        parent_cmd LIKE '/usr/bin/env -i % HOMEBREW_BREW_FILE=%'
    )
    AND NOT (
        pe.euid > 500 AND
        parent_name = 'ruby' AND
        parent_cmd LIKE '%/opt/homebrew/Library/Homebrew/brew.rb%'
    )
GROUP BY pe.pid