-- Detect unusual calls to xattr, used to remove filesystem attributes
--
-- false positives:
--   * none observed, but they are expected
--
-- interval: 60
-- platform: darwin
-- tags: process events
SELECT pe.path AS path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS name,
  TRIM(pe.cmdline) AS cmd,
  pe.pid AS pid,
  pe.euid AS euid,
  pe.parent AS parent_pid,
  TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
  TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
  REGEX_MATCH (
    IIF(pp.path != NULL, pp.path, ppe.path),
    '.*/(.*)',
    1
  ) AS parent_name,
  TRIM(IIF(pp.path != NULL, hash.sha256, ehash.sha256)) AS parent_hash,
  TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
  TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
  REGEX_MATCH (
    IIF(gp.path != NULL, gp.path, gpe.path),
    '.*/(.*)',
    1
  ) AS gparent_name,
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid,
  IIF(
    signature.identifier != NULL,
    signature.identifier,
    esignature.identifier
  ) AS parent_identifier,
  IIF(
    signature.authority != NULL,
    signature.authority,
    esignature.authority
  ) AS parent_authority
FROM process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash ON pp.path = hash.path
  LEFT JOIN hash ehash ON ppe.path = ehash.path
  LEFT JOIN signature ON pp.path = signature.path
  LEFT JOIN signature esignature ON ppe.path = esignature.path
WHERE pe.path = '/usr/bin/xattr'
  AND pe.status = 0
  AND pe.time > (strftime('%s', 'now') -60)
  AND cmd NOT IN (
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper (GPU).app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper (Plugin).app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper (Renderer).app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/Keybase.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Library/LoginItems/1Password Browser Helper.app',
    'xattr -d -r com.apple.quarantine /Applications/Google Chrome.app'
  )
  AND NOT (
    pe.euid > 500
    AND cmd LIKE '%xattr -l %'
  )
  AND NOT (
    pe.euid > 500
    AND cmd LIKE '%xattr -p com.apple.quarantine %'
  )
  AND NOT (
    pe.euid > 500
    AND cmd = '/usr/bin/xattr -h'
    AND parent_cmd LIKE '%homebrew%'
  )
  AND cmd NOT LIKE '/usr/bin/xattr -w com.apple.quarantine 0002;%'
  AND cmd NOT LIKE '/usr/bin/xattr -w com.apple.quarantine 0181;%'
GROUP BY pe.pid, cmd
