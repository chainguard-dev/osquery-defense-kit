-- Unexpected calls to macOS system utilities (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1497/001/ (Virtualization/Sandbox Evasion: System Checks)
--   * https://www.sentinelone.com/blog/atomic-stealer-threat-actor-spawns-second-variant-of-macos-malware-sold-on-telegram/
--
-- platform: darwin
-- interval: 900
SELECT
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS exception_key,
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.time AS p0_time,
  pe.pid AS p0_pid,
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
  ) AS p2_authority
FROM
  process_events pe
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
  pe.time > (strftime('%s', 'now') -900)
  AND pe.status = 0
  AND pe.parent > 0
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND pe.status == 0
  AND pe.path IN (
    '/usr/bin/csrutil',
    '/usr/bin/ditto',
    '/usr/bin/dscl',
    '/usr/bin/funzip',
    '/usr/bin/openssl',
    '/usr/bin/security',
    '/usr/bin/sqlite3',
    '/usr/bin/sw_vers',
    '/usr/bin/unzip',
    '/usr/bin/uuidgen',
    '/usr/bin/whoami',
    '/usr/libexec/security_authtrampoline',
    '/usr/sbin/ioreg',
    '/usr/sbin/sysctl',
    '/usr/sbin/system_profiler'
  )
  AND p.parent > 0
  AND NOT p0_cmd IN (
    'sysctl -i sysctl.proc_translated',
    'sysctl -n hw.optional.arm64',
    'sw_vers -productName',
    'sysctl -n sysctl.proc_translated',
    '/usr/sbin/sysctl kern.hv_support',
    '/usr/sbin/sysctl -n hw.cputype',
    '/usr/sbin/sysctl sysctl.proc_translated'
  )
  AND NOT exception_key IN (
    'system_profiler,500,Google Drive,launchd',
    'system_profiler,500,bash,launchd',
    'system_profiler,500,steam_osx,launchd',
    'system_profiler,500,bash,logioptionsplus_agent',
    'system_profiler,0,launcher,launchd'
  )
  AND NOT p0_cmd LIKE '/usr/libexec/security_authtrampoline /Library/Application Support/Adobe/Adobe Desktop Common/ElevationManager/Adobe Installer auth%'
  AND NOT p0_cmd LIKE '%sqlite3%vulnerability.db%'
  AND NOT p1_path IN (
    '/Applications/LogiTune.app/Contents/MacOS/LogiTune',
    '/Applications/Alfred 5.app/Contents/Preferences/Alfred Preferences.app/Contents/MacOS/Alfred Preferences'
  )
GROUP BY
  pe.pid
