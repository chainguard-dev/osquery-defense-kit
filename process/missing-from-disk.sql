SELECT p.pid, p.on_disk, p.uid, p.gid, p.name, p.path, p.cmdline, p.parent, pp.on_disk AS parent_on_disk, pp.path AS parent_path, pp.cmdline AS parent_cmdline
FROM processes p
JOIN processes pp ON p.parent = pp.pid
WHERE p.on_disk != 1
AND p.parent != 2 -- kthreadd
AND p.path NOT LIKE "/app/%"
AND p.path NOT LIKE "/usr/libexec/evolution-%"
AND p.path NOT LIKE "/opt/homebrew/Cellar/%"
AND p.path NOT IN (
    '',
    '/opt/google/chrome/chrome_crashpad_handler',
    '/opt/google/chrome/chrome',
    '/opt/google/chrome/nacl_helper',
    '/usr/bin/containerd',
    '/usr/bin/dbus-broker-launch',
    '/usr/bin/dbus-broker',
    '/usr/bin/flatpak-spawn',
    '/usr/bin/gjs-console',
    '/usr/bin/gnome-shell',
    '/usr/bin/wireplumber',
    '/usr/libexec/gnome-shell-calendar-server',
    '/usr/sbin/NetworkManager'
)
AND parent_path NOT IN ('/usr/bin/containerd-shim-runc-v2')
AND p.name NOT IN (
    "firewalld",
    "gopls",
    "Slack",
    "Slack Helper (GPU)",
    "Slack Helper",
    "Slack Helper (Renderer)",
    "mysqld"
)
