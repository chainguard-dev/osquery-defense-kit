-- Suspicious calls to systemctl(event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1543/002/ (Create or Modify System Process: Systemd Service)
--
-- tags: transient process state often
-- platform: linux
-- interval: 300
SELECT -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.time AS p0_time,
  pe.pid AS p0_pid,
  p.cgroup_path AS p0_cgroup,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS exception_key
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  uptime.total_seconds > 30 -- NOTE: The remainder of this query is synced with unexpected-fetcher-parents
  AND pe.path IN (
    '/usr/bin/systemctl',
    '/bin/systemctl',
    '/sbin/systemctl'
  )
  AND pe.cmdline != ''
  AND pe.time > (strftime('%s', 'now') -300)
  AND NOT exception_key IN (
    'systemctl,0,,containerd-shim-runc-v2',
    'systemctl,0,apt-helper,',
    'systemctl,0,bash,pacman',
    'systemctl,0,dash,logrotate',
    'systemctl,0,kubeadm,containerd-shim-runc-v2',
    'systemctl,0,pacman,pacman',
    'systemctl,0,pacman,sudo',
    'systemctl,0,snapd,systemd',
    'systemctl,0,tailscaled,',
    'systemctl,127,snap,systemd',
    'systemctl,500,bash,gnome-terminal-server',
    'systemctl,500,snap,systemd',
    'systemctl,500,systemd,',
    'systemctl,500,zsh,tmux'
  )
  AND NOT p0_cmd IN (
    '/bin/systemctl is-enabled -q whoopsie.path',
    '/bin/systemctl -q is-enabled whoopsie.path',
    '/bin/systemctl --quiet is-enabled whoopsie.path',
    '/bin/systemctl stop --no-block nvidia-persistenced',
    'systemctl --system daemon-reexec',
    '/sbin/runlevel',
    'systemctl is-active systemd-resolved.service',
    'systemctl restart reflector.service',
    'systemctl stop libvirtd.service',
    'systemctl is-enabled power-profiles-daemon.service',
    'systemctl is-enabled snapd.apparmor',
    'systemctl is-enabled systemd-rfkill.service',
    'systemctl is-enabled systemd-rfkill.socket',
    'systemctl is-enabled tlp.service',
    'systemctl restart NetworkManager.service',
    'systemctl kill -s HUP rsyslog.service',
    'systemctl -p LoadState show cups.service',
    'systemctl -q is-enabled whoopsie',
    'systemctl --quiet is-enabled cups.service',
    'systemctl reboot',
    'systemctl restart cups.service',
    'systemctl status kubelet',
    'systemctl stop kubelet',
    'systemctl --user import-environment DISPLAY XAUTHORITY',
    '/usr/bin/systemctl try-reload-or-restart dbus'
  ) -- apt-helper form
  AND NOT p0_cmd LIKE '%systemctl is-active -q %.service'
  AND NOT p0_cmd LIKE '%systemctl show --property=%'
  AND NOT p0_cmd LIKE '%systemctl % snap-kubectl-%.mount'
  AND NOT p0_cmd LIKE '%systemctl --user set-environment DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%/bus'
GROUP BY
  pe.pid
