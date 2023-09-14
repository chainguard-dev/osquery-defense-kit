-- Suspicious parenting of network utilities (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1016/ (System Network Configuration Discovery)
--
-- tags: transient process state often
-- platform: linux
-- interval: 300
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.time,
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
  ) AS p2_name
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  uptime.total_seconds > 30
  AND pe.path IN (
    '/usr/bin/ifconfig',
    '/usr/bin/ip',
    '/usr/bin/iptables',
    '/usr/bin/ufw',
    '/usr/bin/nft',
    '/bin/ifconfig',
    '/bin/ip',
    '/bin/iptables',
    '/bin/ufw',
    '/bin/nft',
    '/sbin/ifconfig',
    '/sbin/ip',
    '/sbin/iptables',
    '/sbin/ufw',
    '/sbin/nft'
  )
  AND pe.cmdline != ''
  AND pe.time > (strftime('%s', 'now') -300)
  AND NOT (
    pe.euid > 500
    AND p1_name IN ('sh', 'fish', 'zsh', 'bash', 'dash', 'nu')
    AND p2_name IN (
      'alacritty',
      'gnome-terminal-',
      'kitty',
      'login',
      'roxterm',
      'tmux',
      'tmux:server',
      'wezterm-gui',
      'zsh'
    )
  )
  AND NOT p1_cmd IN (
    '/bin/sh /etc/network/if-up.d/avahi-autoipd',
    '/usr/bin/libvirtd --timeout 120'
  )
  AND NOT p1_path IN ('/usr/libexec/gvfsd')
  AND NOT p0_cmd LIKE '%ip route add % dev % metric 1000 scope link'
  AND NOT p0_cmd LIKE '%ip link set lo netns -1'
GROUP BY
  pe.pid
