SELECT p.pid, p.cmdline, p.path, mnt_namespace, p.cwd,
p.on_disk, p.state, pp.on_disk AS parent_on_disk, pp.path AS parent_path, pp.cmdline AS parent_cmdline, pp.cwd AS parent_cwd,
ph.sha256 AS parent_sha256
FROM processes p
LEFT JOIN process_namespaces ON p.pid=process_namespaces.pid
LEFT JOIN processes pp ON p.parent = pp.pid
LEFT JOIN hash ph ON pp.path = ph.path
WHERE p.on_disk != 1 AND p.path != ""
-- use osquery as the reference mount namespace
AND mnt_namespace IN (
        SELECT DISTINCT(mnt_namespace)
        FROM process_namespaces
        JOIN processes ON processes.pid = process_namespaces.pid
        WHERE processes.name IN ('osqueryi', 'osqueryd')
)
AND p.path NOT IN (
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

-- AppImage
AND p.path NOT LIKE "/tmp/.mount_%/usr/bin/%"
AND p.path NOT LIKE "/Users/%/%/%.test"