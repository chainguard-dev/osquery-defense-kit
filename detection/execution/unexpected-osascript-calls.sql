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
-- interval: 60
-- platform: darwin
-- tags: process events
SELECT
  p.pid,
  p.path,
  TRIM(p.cmdline) AS cmd,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  pp.name AS parent_name,
  -- not available in process_events
  MAX(pp.path, ppe.path) AS parent_path,
  TRIM(MAX(pp.cmdline, ppe.cmdline)) AS parent_cmd,
  MAX(pp.euid, ppe.euid) AS parent_euid,
  MAX(hash.sha256, ehash.sha256) AS parent_sha256,
  MAX(signature.identifier, esignature.identifier) AS parent_identifier,
  MAX(signature.authority, esignature.authority) AS parent_auth,
  CONCAT (
    MAX(signature.identifier, esignature.identifier),
    ",",
    MAX(signature.authority, esignature.authority),
    ",",
    SUBSTR(TRIM(p.cmdline), 0, 54)
  ) AS exception_key
FROM
  uptime,
  process_events p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN process_events ppe ON p.parent = ppe.pid
  LEFT JOIN hash ON pp.path = hash.path
  LEFT JOIN hash ehash ON ppe.path = ehash.path
  LEFT JOIN signature ON pp.path = signature.path
  LEFT JOIN signature esignature ON ppe.path = esignature.path
WHERE
  p.path IN ('/usr/bin/osascript', '/usr/bin/osacompile')
  AND p.time > (strftime('%s', 'now') -60)
  AND exception_key NOT IN (
    ',,osascript',
    ',,osascript openChrome.applescript https://localhost.ch',
    'com.vng.zalo,Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM),osascript -ss'
  )
  AND cmd NOT IN ('osascript -e user locale of (get system info)')
  AND cmd NOT LIKE '/usr/bin/osascript /Users/%/Library/Caches/com.runningwithcrayons.Alfred/Workflow Scripts/%'
  -- We don't want to allow all of Python as an exception
  AND NOT (
    exception_key = 'org.python.python,,osascript'
    AND parent_cmd LIKE '% /opt/homebrew/bin/jupyter-notebook'
  )
  AND NOT (
    exception_key = 'org.python.python,Software Signing,osascript'
    AND (
      parent_cmd LIKE '%/Contents/MacOS/Python -S %/google-cloud-sdk/lib/gcloud.py auth login'
      OR parent_cmd LIKE '%/bin/gcloud auth login'
    )
  )
  AND NOT cmd LIKE 'osascript -e set zoomStatus to "closed"%'
  AND NOT cmd LIKE 'osascript openChrome.applescript http://127.0.0.1:%'
  AND NOT cmd LIKE 'osascript openChrome.applescript http%://localhost%'
  AND NOT cmd LIKE '/usr/bin/osascript /Users/%/osx-trash/trashfile.AppleScript %'
  AND NOT cmd LIKE 'osascript -e%tell application "System Preferences"%reveal anchor "shortcutsTab"%"com.apple.preference.keyboard"'
GROUP BY
  p.pid
