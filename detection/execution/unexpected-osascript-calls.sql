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
-- interval: 300
-- platform: darwin
-- tags: process events
SELECT
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
  pe.path IN ('/usr/bin/osascript', '/usr/bin/osacompile')
  AND pe.time > (strftime('%s', 'now') -300)
  AND pe.cmdline != ''
  -- Only include successful executions: On macOS, process_events includes unsuccessful path lookups!
  AND pe.status = 0
  AND NOT (
    pe.euid > 500
    AND (
      p0_cmd IN (
        'osascript -e user locale of (get system info)',
        'osascript -e tell application "Finder" to reveal application file id "com.garmin.renu.client"',
        'osascript ./ExpressLoginItem.scpt',
        'osascript -e get POSIX path of (path to application id "com.garmin.LifetimeMapUpdate")',
        'osascript -e get POSIX path of (path to application id "com.garmin.expressfit")',
        'osascript -e get POSIX path of (path to application id "com.garmin.antagent")'
      )
      OR p0_cmd LIKE '%"CFBundleName" of property list file (app_path & ":Contents:Info.plist")'
      OR p0_cmd LIKE 'osascript -e set zoomStatus to "closed"%'
      OR p0_cmd LIKE 'osascript -l JavaScript%com.elgato.StreamDeck%'
      OR p0_cmd LIKE 'osascript -e%tell application "System Preferences"%reveal anchor "shortcutsTab"%"com.apple.preference.keyboard"'
      OR p0_cmd LIKE 'osascript -e tell application "zoom.us"%'
      OR p0_cmd LIKE 'osascript -l JavaScript /tmp/PKInstallSandbox.%/Scripts/org.gpgtools.gpgmailloader.pkg.%/mailbundle-enabled.jxa -- GPGMailLoader.mailbundle'
      OR p0_cmd LIKE 'osascript openChrome.applescript http://127.0.0.1:%'
      OR p0_cmd LIKE 'osascript openChrome.applescript http%://localhost%'
      OR p0_cmd LIKE '/usr/bin/osascript /Applications/Amazon Photos.app/Contents/Resources/quit_and_restart_app.scpt /Applications/Amazon Photos.app com.amazon.clouddrive.mac%'
      OR p0_cmd LIKE '/usr/bin/osascript /Users/%/Library/Caches/com.runningwithcrayons.Alfred/Workflow Scripts/%'
      OR p0_cmd LIKE '/usr/bin/osascript /Users/%/osx-trash/trashfile.AppleScript %'
      OR p1_cmd LIKE '%aws %sso%'
      OR p1_cmd LIKE '%gcloud% auth %login%'
      OR p1_cmd LIKE '% /opt/homebrew/bin/jupyter%notebook'
      OR p1_cmd LIKE '/bin/sh %/opt/homebrew/bin/git-gui%'
      OR p1_authority = 'Developer ID Application: Docker Inc (9BNSXJN65R)'
      OR p1_name IN ('yubikey-agent')
      OR (
        p1_authority = 'Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM)'
        AND p0_cmd = 'osascript -ss'
      )
      OR (
        p1_authority = 'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)'
        AND p0_cmd = 'osascript'
      )
    )
  )
  -- The following apply to all uids
  AND NOT p0_cmd IN (
    'osascript -e do shell script "/bin/rm -Rf /opt/vagrant /usr/local/bin/vagrant" with administrator privileges',
    'osascript -e user locale of (get system info)',
    '/usr/bin/osascript -e do shell script "/bin/rm -Rf /opt/vagrant /usr/local/bin/vagrant" with administrator privileges'
  )
GROUP BY
  pe.pid
