-- Suspicious parenting of fetch tools (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1016/ (System Network Configuration Discovery)
--
-- tags: transient process state often
-- platform: darwin
-- interval: 600
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.time AS p0_time,
  pe.euid AS p0_euid,
  s.authority AS p0_authority,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  pe_sig1.authority AS p1_authority,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
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
  COALESCE(
    p1_p2_sig.authority,
    pe1_p2_sig.authority,
    pe1_pe2_sig.authority
  ) AS p2_authority,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS exception_key
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN signature s ON pe.path = s.path
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  LEFT JOIN signature pe_sig1 ON pe1.path = pe_sig1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
  LEFT JOIN signature p1_p2_sig ON p1_p2.path = p1_p2_sig.path
  LEFT JOIN signature pe1_p2_sig ON pe1_p2.path = pe1_p2_sig.path
  LEFT JOIN signature pe1_pe2_sig ON pe1_pe2.path = pe1_pe2_sig.path
WHERE
  pe.path IN (
    '/sbin/ifconfig',
    '/usr/sbin/netstat',
    '/usr/bin/nscurl',
    '/sbin/pfctl',
    '/usr/libexec/ApplicationFirewall/socketfilterfw'
  )
  AND uptime.total_seconds > 30
  AND pe.time > (strftime('%s', 'now') -600)
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND pe.status == 0
  AND NOT (
    pe.euid > 500
    AND p1_name IN ('sh', 'fish', 'zsh', 'bash', 'dash')
    AND p2_name IN (
      'kitty',
      'login',
      'tmux',
      'ShellLauncher',
      'sudo',
      'tmux:server',
      'zsh'
    )
  )
  AND NOT exception_key IN (
    'netstat,500,IPNExtension,launchd',
    'pfctl,0,pia-daemon,launchd',
    'netstat,500,AccountSubscriber,launchd',
    'netstat,500,coresymbolicationd,launchd',
    'ifconfig,500,zsh,stable',
    'netstat,0,io.tailscale.ipn.macsys.network-extension,launchd',
    'ifconfig,0,pia-openvpn,pia-daemon',
    'ifconfig,0,pia-openvpn,pia-daemon',
    'ifconfig,0,pia-daemon,launchd',
    'netstat,0,pia-daemon,launchd',
    'pfctl,0,bash,pia-daemon'
  )
  AND p1_cmd NOT IN ('/bin/sh /etc/periodic/daily/420.status-network')
  AND p1_authority != 'Software Signing'
GROUP BY
  pe.pid
