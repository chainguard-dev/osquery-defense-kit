-- Find processes that run with a lower effective UID than their parent (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation-events.sql
--
-- tags: transient state process escalation
-- platform: darwin
SELECT
  s.authority AS p0_auth,
  s.identifier AS p0_id,
  p0.uid AS p0_uid,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
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
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.euid < p0.uid
  AND p0.path NOT IN (
    '',
    '/bin/ps',
    '/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Service',
    '/Library/Application Support/org.pqrs/Karabiner-Elements/bin/karabiner_session_monitor',
    '/Library/DropboxHelperTools/Dropbox_u501/dbkextd',
    '/usr/bin/login',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/bin/top',
    '/usr/local/bin/doas',
    '/Applications/VMware Fusion.app/Contents/Library/vmware-vmx'
  )
  AND NOT (
    p0.path LIKE '/var/folders/%/T/CanonOFI_TEMP/Data/Software/Install/UniversalInstaller.app/Contents/Frameworks/UIx.framework/Resources/relay'
    AND s.authority = 'Developer ID Application: Canon Inc. (XE2XNRRXZ5)'
  )
