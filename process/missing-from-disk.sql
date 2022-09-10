SELECT * FROM processes
WHERE on_disk = 0
AND path NOT LIKE "/app/%"
AND path NOT LIKE "/usr/libexec/evolution-%"
AND path NOT LIKE "/opt/homebrew/Cellar/%"
AND path NOT IN (
    "/bin/registry",
    "/usr/bin/flatpak-spawn",
    "/usr/libexec/webkit2gtk%",
    "/usr/bin/gnome-shell",
    "/usr/libexec/gnome-shell-calendar-server",
    "/usr/bin/python3.10",
    "/usr/sbin/NetworkManager",
    "/usr/bin/gnome-software",
    "/usr/libexec/gnome-shell-calendar-server",
    "/opt/google/chrome/chrome",
    "/opt/google/chrome/chrome_crashpad_handler",
    "/opt/google/chrome/nacl_helper",
    "/usr/bin/containerd",
    "/usr/bin/dbus-broker",
    "/usr/bin/dbus-broker-launch",
    "/usr/bin/gjs-console",
    "/usr/bin/NetworkManager",
    "/usr/bin/wireplumber"
)

AND NAME NOT IN (
    "firewalld",
    "gopls",
    "Slack",
    "Slack Helper (GPU)",
    "Slack Helper",
    "Slack Helper (Renderer)",
    "mysqld"
)
-- TODO: INCLUDE -1 (boopkit)
