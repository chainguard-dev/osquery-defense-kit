-- Detect unusual calls to osascript
--
-- This query does some gymnastics, as the information on the parent process may be
-- found in the 'process' (currently running) or 'process_events' table (recently started).
--
-- In the case of a long-running process that was recently terminated, parent information
-- may not be in either.
--
-- false positives:
--   * none observed, but they are expected
--
-- interval: 900
-- platform: darwin
-- tags: process events
SELECT
  pe.path AS path,
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
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash ON pp.path = hash.path
  LEFT JOIN hash ehash ON ppe.path = ehash.path
  LEFT JOIN signature ON pp.path = signature.path
  LEFT JOIN signature esignature ON ppe.path = esignature.path
WHERE
  pe.path IN ('/usr/bin/osascript', '/usr/bin/osacompile')
  AND pe.time > (strftime('%s', 'now') -900)
  -- Only include successful executions: On macOS, process_events includes unsuccessful path lookups!
  AND pe.status = 0
  AND NOT (
    pe.euid > 500
    AND (
      cmd IN ('osascript -e user locale of (get system info)')
      OR cmd LIKE '%"CFBundleName" of property list file (app_path & ":Contents:Info.plist")'
      OR cmd LIKE 'osascript -e set zoomStatus to "closed"%'
      OR cmd LIKE 'osascript -e%tell application "System Preferences"%reveal anchor "shortcutsTab"%"com.apple.preference.keyboard"'
      OR cmd LIKE 'osascript -e tell application "zoom.us"%'
      OR cmd LIKE 'osascript openChrome.applescript http://127.0.0.1:%'
      OR cmd LIKE 'osascript openChrome.applescript http%://localhost%'
      OR cmd LIKE '/usr/bin/osascript /Users/%/Library/Caches/com.runningwithcrayons.Alfred/Workflow Scripts/%'
      OR cmd LIKE '/usr/bin/osascript /Users/%/osx-trash/trashfile.AppleScript %'
      OR cmd LIKE '/usr/bin/osascript /Applications/Amazon Photos.app/Contents/Resources/quit_and_restart_app.scpt /Applications/Amazon Photos.app com.amazon.clouddrive.mac%'
      OR parent_cmd LIKE '%/bin/gcloud auth%login'
      OR parent_cmd LIKE '%/google-cloud-sdk/lib/gcloud.py auth%login'
      OR parent_cmd LIKE '% /opt/homebrew/bin/jupyter%notebook'
      OR parent_name IN ('yubikey-agent')
      OR (
        parent_authority = 'Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM)'
        AND cmd = 'osascript -ss'
      )
    )
  )
  -- The following apply to all uids
  AND NOT cmd = 'osascript -e user locale of (get system info)'
GROUP BY
  pe.pid,
  pe.cmd
