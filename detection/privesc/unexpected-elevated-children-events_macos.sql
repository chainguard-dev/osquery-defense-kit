-- Find processes that run with a lower effective UID than their parent (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation.sql
--
-- tags: events process escalation disabled
-- platform: darwin
-- interval: 300
SELECT -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.uid AS p0_uid,
  pe.euid AS p0_euid,
  s.authority AS p0_authority,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p1.euid, pe1.euid) AS p1_euid,
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
  LEFT JOIN signature s ON pe.path = s.path -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  AND p1.start_time <= pe.time
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.time <= pe.time
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  LEFT JOIN signature pe_sig1 ON pe1.path = pe_sig1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid
  AND p1_p2.start_time <= p1.start_time
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid
  AND pe1_p2.start_time <= pe1.time
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
  LEFT JOIN signature p1_p2_sig ON p1_p2.path = p1_p2_sig.path
  LEFT JOIN signature pe1_p2_sig ON pe1_p2.path = pe1_p2_sig.path
  LEFT JOIN signature pe1_pe2_sig ON pe1_pe2.path = pe1_pe2_sig.path
WHERE
  pe.time > (strftime('%s', 'now') -300)
  AND p0_euid < p1_euid
  AND pe.status = 0
  AND pe.parent > 0
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND p1_path NOT IN (
    '/Applications/LogiTune.app/Contents/MacOS/LogiTune',
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared',
    '/System/Library/PrivateFrameworks/AOSKit.framework/Versions/A/XPCServices/com.apple.iCloudHelper.xpc/Contents/MacOS/com.apple.iCloudHelper',
    '/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/XPCServices/XProtectPluginService.xpc/Contents/MacOS/XProtectPluginService',
    '/usr/bin/login',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/libexec/mdmclient',
    '/usr/libexec/PerfPowerServicesExtended',
    '/usr/local/bin/doas'
  ) -- Exclude weird bad data we've seen due to badly recorded macOS parent/child relationships, fixable by reboot
  AND NOT p0_cmd IN (
    '/usr/sbin/cupsd -l',
    '/usr/sbin/cfprefsd agent',
    '/usr/libexec/wifip2pd',
    '/System/Library/CoreServices/iconservicesd',
    '/System/Library/PrivateFrameworks/InstallCoordination.framework/Support/installcoordinationd',
    '/System/Library/PrivateFrameworks/CoreSymbolication.framework/coresymbolicationd',
    '/usr/libexec/PerfPowerServicesExtended',
    '/usr/libexec/mdmclient daemon',
    '/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared -s mdworker -c MDSImporterWorker -m com.apple.mdworker.shared'
  )
  AND NOT exception_key IN (
    'amfid,0,com.docker.backend,Docker',
    'biometrickitd,0,LogiTune,launchd',
    'bioutil,0,callservicesd,launchd',
    'com.apple.geod,0,fmfd,launchd',
    'trustd,205,trustd,launchd',
    'CAReportingService,0,LogiTune,launchd',
    'efilogin-helper,0,containermanagerd,launchd',
    'com.apple.AccountPolicyHelper,0,LogiTune,launchd',
    'com.apple.geod,262,com.docker.backend,Docker',
    'com.apple.WebKit.WebContent,200,zsh,Emacs-arm64-11',
    'containermanagerd,262,com.docker.backend,Docker',
    'dprivacyd,0,com.docker.backend,Docker',
    'SCHelper,0,com.docker.backend,Docker',
    'suhelperd,0,LogiTune,launchd',
    'sysextd,0,LogiTune,launchd',
    'system_profiler,0,callservicesd,launchd'
  )
  AND NOT (
    pe.euid = 262 -- core media helper id
    AND pe.path = '/System/Library/Frameworks/CoreMediaIO.framework/Versions/A/Resources/AppleCamera.plugin/Contents/Resources/AppleCameraAssistant'
  )
