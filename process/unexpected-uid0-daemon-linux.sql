SELECT p.pid,
    p.name,
    p.path,
    p.euid,
    p.gid,
    f.ctime,
    f.directory AS dirname,
    p.cmdline,
    mnt_namespace,
    hash.sha256,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline
FROM processes p
    LEFT JOIN file f ON p.path = f.path
    LEFT JOIN process_namespaces ON p.pid = process_namespaces.pid
    LEFT JOIN hash ON p.path = hash.path
    LEFT JOIN processes pp ON p.parent = pp.pid
WHERE p.uid = 0
    AND (strftime('%s', 'now') - p.start_time) > 120
    -- use osquery as the reference mount namespace
    AND mnt_namespace IN (
        SELECT DISTINCT (mnt_namespace)
        FROM process_namespaces
            JOIN processes ON processes.pid = process_namespaces.pid
        WHERE processes.name IN ("osqueryi", "osqueryd")
    )
    AND p.path NOT IN (
        "", -- Not a file-based process
        "/usr/lib/systemd/systemd",
        "/usr/sbin/tailscaled",
        "/usr/bin/dockerd",
        "/usr/libexec/flatpak-system-helper",
        "/usr/bin/containerd",
        "/usr/sbin/anacron",
        "/sbin/apcupsd",
        "/usr/bin/apcupsd",
        "/usr/bin/sshd",
        "/usr/bin/gpg-agent",
        "/usr/libexec/scdaemon",
        "/usr/libexec/docker/docker-proxy",
        "/usr/bin/containerd-shim-runc-v2",
        "/usr/sbin/pcscd",
        "/usr/lib/systemd/systemd-journald",
        "/usr/libexec/accounts-daemon",
        "/usr/lib/systemd/systemd-homed",
        "/usr/lib/systemd/systemd-machined",
        "/usr/libexec/udisks2/udisksd",
        "/usr/sbin/alsactl",
        "/usr/sbin/abrtd",
        "/usr/bin/abrt-dump-journal-core",
        "/usr/bin/abrt-dump-journal-oops",
        "/usr/bin/abrt-dump-journal-xorg",
        "/usr/sbin/cupsd",
        "/usr/sbin/gssproxy",
        "/usr/sbin/wpa_supplicant",
        "/usr/sbin/abrt-dbus",
        "/usr/sbin/gdm",
        "/usr/libexec/packagekitd",
        "/usr/libexec/gdm-session-worker",
        "/usr/bin/docker-proxy",
        "/usr/bin/journalctl",
        "/usr/lib/udisks2/udisksd",
        "/usr/bin/crond",
        "/usr/bin/lightdm",
        "/usr/lib/Xorg",
        "/usr/bin/osqueryd",
        "/usr/bin/wpa_supplicant",
        "/usr/sbin/cups-browsed",
        "/usr/sbin/acpid",
        "/usr/sbin/cron",
        "/usr/libexec/polkitd",
        "/usr/sbin/zed",
        "/usr/sbin/gdm3",
        "/usr/libexec/snapd/snapd",
        "/usr/libexec/sssd/sssd_kcm",
        "/usr/bin/tailscaled",
        "/usr/lib/gdm-session-worker",
        "/usr/bin/gdm",
        "/snap/snapd/17029/usr/lib/snapd/snapd"
    )
    -- Because I don't want to whitelist all of Python3
    AND p.cmdline NOT IN (
        "/usr/bin/python3 -s /usr/sbin/firewalld --nofork --nopid",
        "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal",
        "/usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers"
    )
    AND p.path NOT LIKE "/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd"
    AND p.path NOT LIKE "/usr/local/kolide-k2/bin/launcher-updates/%/launcher"
    AND p.path NOT LIKE "/nix/store/%/bin/%"
    AND p.path NOT LIKE "/nix/store/%-systemd-%/lib/systemd/systemd%"
    AND p.path NOT LIKE "/nix/store/%/libexec/%"
    AND p.path NOT LIKE "/snap/snapd/%/usr/lib/snapd/snapd"