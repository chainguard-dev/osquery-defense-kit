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
  p.pid,
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
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN process_namespaces ON p.pid = process_namespaces.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE
  p.uid = 0
  AND (strftime('%s', 'now') - p.start_time) > 15 -- use osquery as the reference mount namespace
  AND mnt_namespace IN (
    SELECT DISTINCT
      (mnt_namespace)
    FROM
      process_namespaces
      JOIN processes ON processes.pid = process_namespaces.pid
    WHERE
      processes.name IN ('osqueryi', 'osqueryd')
  )
  AND p.path NOT IN (
    '',
    '/sbin/apcupsd',
    '/usr/bin/abrt-dump-journal-core',
    '/usr/bin/abrt-dump-journal-oops',
    '/usr/bin/abrt-dump-journal-xorg',
    '/usr/bin/anacron',
    '/usr/bin/apcupsd',
    '/usr/bin/clamscan',
    '/usr/bin/containerd',
    '/usr/bin/containerd-shim-runc-v2',
    '/usr/bin/crond',
    '/usr/bin/dbus-daemon',
    '/usr/bin/dbus-launch',
    '/usr/bin/dockerd',
    '/usr/bin/docker-proxy',
    '/usr/bin/fish',
    '/usr/bin/gdm',
    '/usr/bin/vim',
    '/usr/bin/gpg-agent',
    '/usr/bin/journalctl',
    '/usr/bin/lightdm',
    '/usr/bin/osqueryd',
    '/usr/bin/pacman',
    '/usr/bin/sshd',
    '/usr/bin/tailscaled',
    '/usr/bin/wpa_supplicant',
    '/usr/libexec/accounts-daemon',
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
    '/usr/lib/systemd/systemd-homed',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd-machined',
    '/usr/lib/udisks2/udisksd',
    '/usr/lib/Xorg',
    '/usr/sbin/abrtd',
    '/usr/sbin/abrt-dbus',
    '/usr/sbin/acpid',
    '/usr/sbin/alsactl',
    '/usr/sbin/anacron',
    '/usr/sbin/cron',
    '/usr/sbin/cups-browsed',
    '/usr/sbin/cupsd',
    '/usr/sbin/gdm',
    '/usr/sbin/gdm3',
    '/usr/sbin/gssproxy',
    '/usr/sbin/mcelog',
    '/usr/sbin/pcscd',
    '/usr/sbin/tailscaled',
    '/usr/sbin/thermald',
    '/usr/sbin/wpa_supplicant',
    '/usr/sbin/zed'
  )
  -- Because I don't want to whitelist all of Python3
  AND p.cmdline NOT IN (
    'xargs logger -s',
    '/usr/bin/xargs',
    '/usr/bin/python3 -s /usr/sbin/firewalld --nofork --nopid',
    '/usr/bin/python /usr/bin/firewalld --nofork --nopid',
    '/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal',
    '/usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers'
  )
  AND NOT p.cmdline LIKE '/usr/bin/python3 /usr/bin/dnf %'
  AND p.path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND p.path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/launcher'
  AND p.path NOT LIKE '/nix/store/%/bin/%'
  AND p.path NOT LIKE '/nix/store/%-systemd-%/lib/systemd/systemd%'
  AND p.path NOT LIKE '/nix/store/%/libexec/%'
  AND p.path NOT LIKE '/snap/snapd/%/usr/lib/snapd/snapd'
