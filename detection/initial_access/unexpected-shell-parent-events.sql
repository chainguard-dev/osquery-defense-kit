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
SELECT pe.path AS child_path,
    REGEX_MATCH (pe.path, '.*/(.*)', 1) AS child_name,
    pe.cmdline AS child_cmd,
    pe.pid AS child_pid,
    p.cgroup_path AS child_cgroup,
    p.parent AS parent_pid,
    TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
    TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
    REGEX_MATCH (IIF(pp.path != NULL, pp.path, ppe.path), '.*/(.*)', 1) AS parent_name,

    TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
    TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
    REGEX_MATCH (IIF(gp.path != NULL, gp.path, gpe.path), '.*/(.*)', 1) AS gparent_name,

    IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid
FROM process_events pe
    LEFT JOIN processes p ON pe.pid = p.pid
    LEFT JOIN processes pp ON pe.parent = pp.pid
    LEFT JOIN process_events ppe ON pe.parent = ppe.pid
    LEFT JOIN processes gp ON gp.pid = pp.parent
    LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
WHERE child_name IN ('sh', 'fish', 'zsh', 'bash', 'dash', 'osascript')
    AND pe.time > (strftime('%s', 'now') -300) -- Ignore partial table joins
    AND NOT (
        parent_name IN (
            'abrt-handle-eve',
            'alacritty',
            'bash',
            'build-script-build',
            'chezmoi',
            'clang-11',
            'code',
            'Code Helper (Renderer)',
            'Code - Insiders Helper (Renderer)',
            'collect2',
            'conmon',
            'containerd-shim',
            'dash',
            'demoit',
            'direnv',
            'doas',
            'erl_child_setup',
            'find',
            'FinderSyncExtension',
            'fish',
            'go',
            'git',
            'goland',
            'helm',
            'i3bar',
            'i3blocks',
            'java',
            'kitty',
            'login',
            'env',
            'ko',
            'kubectl',
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
            'perl',
            'PK-Backend',
            'python',
            'roxterm',
            'sdk',
            'sdzoomplugin',
            'sh',
            'snyk',
            'skhd',
            'sshd',
            'sudo',
            'swift',
            'systemd',
            'terminator',
            'test2json',
            'tmux',
            'tmux:server',
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
        -- Do not add shells to this list if you want your query to detect
        -- bad programs that were started from a shell.
        OR gparent_name IN (
            'env',
            'git'
        )
    )