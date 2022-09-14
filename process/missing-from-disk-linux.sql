SELECT processes.pid, processes.cmdline, processes.path, mnt_namespace
FROM processes
LEFT JOIN process_namespaces ON processes.pid=process_namespaces.pid
WHERE on_disk != 1
-- use osquery as the reference mount namespace
AND mnt_namespace IN (
        SELECT DISTINCT(mnt_namespace)
        FROM process_namespaces
        JOIN processes ON processes.pid = process_namespaces.pid
        WHERE processes.name IN ('osqueryi', 'osqueryd')
)
AND path NOT IN (
    "",
    "/opt/google/chrome/chrome",
    "/usr/bin/containerd",
    "/usr/bin/dbus-broker-launch",
    "/usr/bin/dbus-broker",
    "/usr/bin/wireplumber",
    "/usr/bin/gnome-shell",
    "/usr/libexec/gnome-shell-calendar-server",
    "/usr/bin/gjs-console",
    "/opt/google/chrome/chrome_crashpad_handler",
    "/opt/google/chrome/nacl_helper"
)
