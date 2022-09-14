SELECT p.name,
    p.path AS path,
    p.cmdline AS cmdline,
    pp.name AS parent_name,
    pp.path AS parent_path,
    pp.cmdline AS parent_cmdline,
    hash.sha256 AS parent_sha256
FROM processes p
    LEFT JOIN processes pp ON pp.pid = p.parent
    LEFT JOIN hash ON pp.path = hash.path
WHERE p.name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
    AND parent_name NOT IN (
        'alacritty',
        'bash',
        'Code Helper (Renderer)',
        'dash',
        'demoit',
        'fish',
        'go',
        'goland',
        'monorail',
        'containerd-shim',
        'roxterm',
        'kubectl',
        'sdzoomplugin',
        'systemd',
        'terminator',
        'tmux:server',
        'tmux',
        'wezterm-gui',
        'xfce4-terminal',
        'zsh'
    )
    AND parent_path NOT IN (
        '/opt/X11/libexec/launchd_startx',
        '/usr/bin/alacritty',
        '/usr/bin/crond',
        '/usr/libexec/gnome-terminal-server',
        '/sbin/launchd',
        '/usr/bin/login'
    )

    -- npm run server
    AND NOT p.cmdline IN (
        'sh -c -- exec-bin node_modules/.bin/hugo/hugo server'
    )

    AND NOT parent_cmdline LIKE "/Applications/Warp.app/%"
    AND NOT parent_name LIKE "Emacs%"
    AND NOT parent_name LIKE "%term%"
    AND NOT parent_name LIKE "%Term%"
