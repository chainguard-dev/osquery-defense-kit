-- Unexpected long-running processes running as root
--
-- false positives:
--   * new software requiring escalated privileges
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/
--
-- tags: persistent process state
-- platform: linux
SELECT
  DATETIME(f.ctime, 'unixepoch') AS p0_changed,
  DATETIME(f.mtime, 'unixepoch') AS p0_modified,
  (strftime('%s', 'now') - p0.start_time) AS p0_runtime_s,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.euid = 0
  AND p0.parent > 0
  AND (strftime('%s', 'now') - p0.start_time) > 15
  AND p0.path NOT IN (
    '',
    '/sbin/apcupsd',
    '/sbin/mount.ntfs',
    '/usr/bin/abrt-dump-journal-core',
    '/usr/bin/abrt-dump-journal-oops',
    '/usr/bin/abrt-dump-journal-xorg',
    '/usr/bin/anacron',
    '/usr/bin/NetworkManager',
    '/usr/lib/upowerd',
    '/usr/bin/fusermount3',
    '/usr/bin/apcupsd',
    '/usr/bin/bash',
    '/usr/bin/clamscan',
    '/usr/lib/fwupd/fwupd',
    '/usr/lib/accounts-daemon',
    '/usr/lib/systemd/systemd-logind',
    '/usr/lib/boltd',
    '/usr/lib/power-profiles-daemon',
    '/usr/bin/udevadm',
    '/usr/bin/doas',
    '/usr/bin/auditd',
    '/usr/lib/boltd',
    '/usr/lib/bluetooth/bluetoothd',
    '/usr/bin/containerd',
    '/usr/bin/containerd-shim-runc-v2',
    '/usr/bin/crond',
    '/usr/bin/dbus-broker',
    '/usr/bin/nvidia-powerd',
    '/usr/bin/dbus-broker-launch',
    '/usr/bin/dbus-daemon',
    '/usr/bin/dbus-launch',
    '/usr/bin/dnsmasq',
    '/usr/bin/dockerd',
    '/usr/bin/docker-proxy',
    '/usr/bin/fish',
    '/usr/bin/gdm',
    '/usr/bin/gpg-agent',
    '/usr/bin/journalctl',
    '/usr/bin/lightdm',
    '/usr/bin/osqueryd',
    '/usr/bin/pacman',
    '/usr/bin/sshd',
    '/usr/bin/system76-power',
    '/usr/bin/system76-scheduler',
    '/usr/bin/tailscaled',
    '/usr/bin/touchegg',
    '/usr/bin/vim',
    '/usr/bin/virtlogd',
    '/usr/bin/wpa_supplicant',
    '/usr/bin/xargs',
    '/usr/lib/accountsservice/accounts-daemon',
    '/usr/libexec/accounts-daemon',
    '/usr/libexec/at-spi-bus-launcher',
    '/usr/libexec/dconf-service',
    '/usr/libexec/docker/docker-proxy',
    '/usr/libexec/flatpak-system-helper',
    '/usr/libexec/gdm-session-worker',
    '/usr/libexec/packagekitd',
    '/usr/libexec/polkitd',
    '/usr/libexec/scdaemon',
    '/usr/libexec/snapd/snapd',
    '/usr/libexec/sssd/sssd_kcm',
    '/usr/libexec/udisks2/udisksd',
    '/usr/libexec/xdg-document-portal',
    '/usr/libexec/xdg-permission-store',
    '/usr/lib/flatpak-system-helper',
    '/usr/lib/gdm-session-worker',
    '/usr/lib/snapd/snapd',
    '/usr/lib/software-properties/software-properties-dbus',
    '/usr/lib/systemd/systemd',
    '/usr/lib/systemd/systemd-fsckd',
    '/usr/lib/systemd/systemd-homed',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd-machined',
    '/usr/lib/udisks2/udisksd',
    '/usr/lib/Xorg',
    '/usr/local/kolide-k2/bin/launcher',
    '/usr/local/kolide-k2/bin/osqueryd',
    '/usr/sbin/abrtd',
    '/usr/sbin/abrt-dbus',
    '/usr/sbin/acpid',
    '/usr/sbin/agetty',
    '/usr/sbin/alsactl',
    '/usr/sbin/anacron',
    '/usr/sbin/atd',
    '/usr/sbin/cron',
    '/usr/sbin/crond',
    '/usr/sbin/cups-browsed',
    '/usr/sbin/cupsd',
    '/usr/sbin/dnsmasq',
    '/usr/sbin/gdm',
    '/usr/sbin/gdm3',
    '/usr/sbin/gssproxy',
    '/usr/sbin/mcelog',
    '/usr/sbin/pcscd',
    '/usr/sbin/pwrstatd',
    '/usr/sbin/rsyslogd',
    '/usr/sbin/smartd',
    '/usr/sbin/sshd',
    '/usr/sbin/tailscaled',
    '/usr/sbin/thermald',
    '/usr/sbin/wpa_supplicant',
    '/usr/sbin/zed'
  )
  -- Because I don't want to whitelist all of Python3
  AND p0.cmdline NOT IN (
    '/bin/sh /usr/lib/apt/apt.systemd.daily lock_is_held',
    '/sbin/init splash',
    '/usr/bin/monitorix -c /etc/monitorix/monitorix.conf -p /run/monitorix.pid',
    '/usr/bin/python3 -s /usr/sbin/firewalld --nofork --nopid',
    '/usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers',
    '/usr/bin/python3 /usr/bin/unattended-upgrade --download-only',
    '/usr/bin/python3 /usr/libexec/blueman-mechanism',
    '/usr/bin/python3 /usr/lib/pop-transition/service.py',
    '/usr/bin/python3 /usr/sbin/execsnoop-bpfcc',
    '/usr/bin/python3 /usr/sbin/lvmdbusd',
    '/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal',
    '/usr/bin/python /usr/bin/firewalld --nofork --nopid',
    '/usr/bin/xargs',
    'xargs logger -s'
  )
  AND NOT p0.cmdline LIKE '/usr/bin/python3 -s% /usr/sbin/firewalld%'
  AND NOT p0.cmdline LIKE '/usr/bin/python3 /usr/bin/dnf %'
  AND NOT p0.cmdline LIKE '/usr/bin/python3 /usr/bin/yum %'
  AND p0.path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND p0.path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/launcher'
  AND p0.path NOT LIKE '/nix/store/%/bin/%'
  AND p0.path NOT LIKE '/nix/store/%-systemd-%/lib/systemd/systemd%'
  AND p0.path NOT LIKE '/nix/store/%/libexec/%'
  AND p0.path NOT LIKE '/snap/snapd/%/usr/lib/snapd/snapd'
  -- Exclude processes running inside of Docker containers
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY p0.pid