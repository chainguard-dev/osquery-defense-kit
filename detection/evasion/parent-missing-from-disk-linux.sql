-- A program where the parent PID is not on disk
--
-- Reveals boopkit if a child is spawned
-- TODO: Make mount namespace aware
--
-- false positives:
--   * none observed
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/004/ (Indicator Removal on Host: File Deletion)
--
-- false positives:
--   * none observed
--
-- tags: persistent daemon
SELECT
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
  p1.cgroup_path AS p1_cgroup,
  p1.path AS p1_path,
  p1.name AS p1_name,
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
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p1.on_disk != 1
  AND p0.on_disk = 1
  AND NOT p0.pid IN (1, 2)
  AND NOT p1.pid IN (1, 2) -- launchd, kthreadd
  AND NOT p1.path IN (
    '/opt/brave.com/brave/brave',
    '/opt/google/chrome/chrome',
    '/usr/bin/alacritty',
    '/usr/bin/roxterm',
    '/usr/bin/doas',
    '/usr/bin/dockerd',
    '/usr/bin/fusermount3',
    '/usr/libexec/at-spi-bus-launcher',
    '/usr/bin/gnome-shell',
    '/usr/bin/ibus-daemon',
    '/usr/bin/kitty',
    '/usr/lib/electron22/electron',
    '/usr/bin/osqueryd',
    '/usr/libexec/gvfsd',
    '/usr/bin/sudo',
    '/usr/bin/tmux',
    '/usr/bin/yay',
    '/usr/libexec/gdm-wayland-session',
    '/usr/libexec/gdm-x-session',
    '/usr/libexec/gnome-terminal-server',
    '/usr/lib/gnome-session-binary',
    '/usr/lib/systemd/systemd',
    '/usr/lib/xdg-document-portal',
    '/usr/sbin/auditd',
    '/usr/sbin/gdm3',
    '/usr/sbin/sshd',
    '/usr/share/code/code'
  ) -- long-running launchers
  AND NOT p1.name IN (
    'bash',
    'dnf',
    'electron',
    'fish',
    'gnome-shell',
    'kubelet',
    'kube-proxy',
    'lightdm',
    'nvim',
    'sh',
    'slack'
  ) -- These alerts were unfortunately useless - lots of spam on macOS
  AND NOT (
    p1.path LIKE '/app/%'
    AND p1.cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/app.slice/%'
  )
  AND NOT p2.name = 'bwrap'
  AND p1.cgroup_path NOT LIKE '/system.slice/docker-%'
  AND p1.cgroup_path != '/system.slice/docker.service'
  AND p1.cgroup_path NOT LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
  AND p1.cgroup_path NOT LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%'
  AND p1.path NOT LIKE '/opt/homebrew/Cellar/%'
  AND p1.path NOT LIKE '/tmp/.mount_%/%'
  AND p1.path NOT LIKE '%google-cloud-sdk/.install/.backup%'
  AND NOT (
    p1.name LIKE 'kworker/%+events_unbound'
    AND p0.name IN ('modprobe')
  )
