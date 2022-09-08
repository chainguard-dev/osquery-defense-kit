SELECT p.name,
    p.path AS path,
    p.cmdline AS cmdline,
    pp.name AS parent_name,
    pp.path AS parent_path,
    pp.cmdline AS parent_cmdline
FROM processes p
    JOIN processes pp ON pp.pid = p.parent
WHERE p.name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
AND NOT (parent_name='alacritty' AND parent_path LIKE '/nix/store/%-alacritty-%/bin/alacritty')
AND NOT (parent_name='alacritty' AND parent_path='/usr/bin/alacritty')
AND NOT (parent_name='bash' AND parent_path LIKE '/nix/store/%-bash-interactive-%/bin/bash')
AND NOT (parent_name='bash' AND parent_path LIKE '/Users/%/homebrew/Cellar/bash/%/bin/bash')
AND NOT (parent_name='bash' AND parent_path='/Applications/GoLand.app/Contents/MacOS/goland')
AND NOT (parent_name='Code Helper (Renderer)' AND parent_path LIKE '/private/var/folders/%/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)')
AND NOT (parent_name='Code Helper (Renderer)' AND parent_path='/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)')
AND NOT (parent_name='crond' AND parent_path='/usr/bin/crond')
AND NOT (parent_name='dash' AND parent_path='/usr/bin/dash')
AND NOT (parent_name='sdzoomplugin' AND path="/bin/bash")
AND NOT (parent_name='Emacs-arm64-11' AND parent_path='/Applications/Emacs.app/Contents/MacOS/Emacs-arm64-11')
AND NOT (parent_name='gnome-terminal-' AND parent_path='/usr/libexec/gnome-terminal-server')
AND NOT (parent_name='launchd_startx' AND parent_path='/opt/X11/libexec/launchd_startx')
AND NOT (parent_name='launchd' AND parent_path='/sbin/launchd')
AND NOT (parent_name='login' AND parent_path='/usr/bin/login')
AND NOT (parent_name='node' AND cmdline LIKE '%lint%')
AND NOT (parent_name='perl' AND cmdline LIKE '%zfs recv%')
AND NOT (parent_name='roxterm' AND parent_path='/usr/bin/roxterm')
AND NOT (parent_name='systemd' AND parent_path='/usr/lib/systemd/systemd')
AND NOT (parent_name='terminator' AND parent_path LIKE '/usr/bin/python3.%')
AND NOT (parent_name='tmux:server' AND parent_path='/usr/bin/tmux')
AND NOT (parent_name='tmux' AND parent_path='/opt/homebrew/Cellar/tmux/3.3a/bin/tmux')
AND NOT (parent_name='wezterm-gui' AND parent_path LIKE '/private/var/folders/%/WezTerm.app/Contents/MacOS/wezterm-gui')
AND NOT (parent_name='xfce4-terminal' AND parent_path='/usr/bin/xfce4-terminal')
AND NOT (parent_name='zsh' AND parent_path='/Applications/Warp.app/Contents/MacOS/stable')
AND NOT (parent_name='zsh' AND parent_path='/bin/zsh')
AND NOT parent_name IN (
    'monorail',
    'go',
    'goland',
    'demoit'
)
