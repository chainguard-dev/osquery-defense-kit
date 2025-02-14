-- Currently running program with Linux red flags
--
-- reference:
--   * https://github.com/timb-machine/linux-malware/blob/725aad34e216cc024c93b04964b289f10f819e6e/defensive/yara/personal-malware-bazaar/unixredflags3.yara
--
-- tags: persistent extra
-- interval: 7200
-- platform: linux
SELECT
  yara.strings,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.start_time AS p0_start,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.start_time AS p1_start,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.start_time AS p2_start,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  JOIN yara ON p0.path = yara.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      start_time > (strftime('%s', 'now') - 7200)
      AND path != ""
    GROUP BY
      path
  )
  AND yara.sigrule = '
    rule redflags {
    strings:
        $avahi = "avahi-daemon:"
        $bash_history = ".bash_history"
        $bin_sh = "/bin/sh"
        $cron = "cron"
        $dev_mqueue = "/dev/mqueue"
        $dev_shm = "/dev/shm"
        $dev_tcp = "/dev/tcp"
        $dev_udp = "/dev/udp"
        $google_chrome = "google-chrome"
        $iptables = "iptables"
        $ld_so = "ld.so.conf"
        $pickup = "pickup -l"
        $proc = "/proc"
        $redhat4 = "Red Hat 4"
        $sudo = "sudo"
        $systemctl = "systemctl"
        $useradd = "useradd"
        $var_run = "/var/run"
        $var_tmp = "/var/tmp"
    condition:
        filesize < 25MB and 5 of them
}'
  AND yara.count > 0
  AND p0.name NOT IN (
    'chrome_crashpad',
    'X',
    'emacs',
    'git',
    'systemd',
    'NetworkManager',
    'systemd-journal',
    'Xorg',
    'slirp4netns',
    'nacl_helper'
  )
  AND p0.path NOT LIKE '%/google/chrome/%'
  AND p0.path NOT LIKE '%/chrome_crashpad_handler'
  AND p0.path NOT LIKE '/nix/store/%/bin/%'
  AND p0.path NOT LIKE '/nix/store/%/libexec/%'
  AND p0.path NOT LIKE '/usr/local/aws-cli/%/aws'
  AND p0.path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/launcher'
  AND p0.path NOT IN (
    '/bin/bash',
    '/bin/containerd-shim-runc-v2',
    '/bin/dash',
    '/bin/fish',
    '/bin/sh',
    '/opt/Elastic/Endpoint/elastic-endpoint',
    '/usr/bin/bash',
    '/usr/bin/containerd-shim-runc-v2',
    '/usr/bin/docker',
    '/usr/bin/docker-proxy',
    '/usr/bin/fish',
    '/usr/bin/gnome-software',
    '/usr/bin/gpg-agent',
    '/usr/bin/ibus-daemon',
    '/usr/bin/make',
    '/usr/bin/NetworkManager',
    '/usr/bin/nvidia-persistenced',
    '/usr/bin/nvim',
    '/usr/bin/pulseaudio',
    '/usr/bin/snap',
    '/usr/bin/sshd',
    '/usr/bin/sudo',
    '/usr/bin/udevadm',
    '/usr/bin/update-notifier',
    '/usr/bin/Xwayland',
    '/usr/lib/bluetooth/bluetoothd',
    '/usr/lib/bluetooth/obexd',
    '/usr/libexec/accounts-daemon',
    '/usr/libexec/bluetooth/bluetoothd',
    '/usr/libexec/bluetooth/obexd',
    '/usr/libexec/flatpak-system-helper',
    '/usr/libexec/sssd/sssd_kcm',
    '/usr/libexec/xdg-desktop-portal',
    '/usr/lib/opt/kolide-k2/bin/launcher',
    '/usr/lib/snapd/snapd',
    '/usr/lib/systemd/systemd',
    '/usr/lib/systemd/systemd-executor',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd-machined',
    '/usr/local/bin/rootlesskit',
    '/usr/local/kolide-k2/bin/launcher',
    '/usr/sbin/acpid',
    '/usr/sbin/auditd',
    '/usr/sbin/cron',
    '/usr/sbin/crond',
    '/usr/sbin/gdm',
    '/usr/sbin/gssproxy',
    '/usr/sbin/mcelog',
    '/usr/sbin/NetworkManager',
    '/usr/sbin/rsyslogd',
    '/usr/sbin/smartd'
  )
