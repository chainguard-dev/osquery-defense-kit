-- Find processes that run with a lower effective UID than their parent (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation.sql
--
-- tags: events process escalation
-- platform: darwin
-- interval: 60
SELECT
  pe.path AS child_path,
  TRIM(REGEX_MATCH (pe.path, '.*/(.*)', 1)) AS child_name,
  TRIM(pe.cmdline) AS child_cmd,
  pe.pid AS child_pid,
  pe.euid AS child_euid,
  p.cgroup_path AS child_cgroup,
  pe.parent AS parent_pid,
  TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
  TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
  (IIF(pp.euid != NULL, pp.euid, ppe.euid)) AS parent_euid,
  IIF(pp.path != NULL, phash.sha256, pehash.sha256) AS parent_hash,
  REGEX_MATCH (
    IIF(pp.path != NULL, pp.path, ppe.path),
    '.*/(.*)',
    1
  ) AS parent_name,
  TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
  TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
  IIF(gp.path != NULL, gphash.sha256, gpehash.path) AS gparent_hash,
  REGEX_MATCH (
    IIF(gp.path != NULL, gp.path, gpe.path),
    '.*/(.*)',
    1
  ) AS gparent_name,
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN hash phash ON pp.path = phash.path
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN hash pehash ON ppe.path = pehash.path
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN hash gphash ON gp.path = gphash.path
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash gpehash ON gpe.path = gpehash.path
WHERE
  pe.time > (strftime('%s', 'now') -60)
  AND child_euid < parent_euid
  AND parent_path NOT IN (
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared',
    '/usr/bin/login',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/local/bin/doas'
  )
  -- Exclude weird bad data we've seen due to badly recorded macOS parent/child relationships, fixable by reboot
  AND NOT (
    child_cmd IN (
      '/usr/sbin/cupsd -l',
      '/usr/libexec/mdmclient daemon',
      '/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared -s mdworker -c MDSImporterWorker -m com.apple.mdworker.shared'
    )
  )
  AND NOT (
    pe.euid = 262 -- core media helper id
    AND pe.path = '/System/Library/Frameworks/CoreMediaIO.framework/Versions/A/Resources/AppleCamera.plugin/Contents/Resources/AppleCameraAssistant'
  )
