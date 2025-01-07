-- Programs which appear to have been touched on macOS
--
-- This check is probably not very useful as there are plenty of legit reasons why
-- the dates (in particular, 'btime'), gets doctored.
--
-- false positives:
--   * Programs which are packaged weirdly and don't follow the typical Apple app layout
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Timestomping)
--
-- tags: transient seldom filesystem state extra
-- platform: darwin
SELECT
  p.path,
  p.name,
  p.cmdline,
  p.euid,
  DATETIME(p.start_time, 'unixepoch') AS started,
  DATETIME(f.ctime, 'unixepoch') AS changed,
  DATETIME(f.btime, 'unixepoch') AS birthed,
  DATETIME(f.mtime, 'unixepoch') AS modified,
  DATETIME(f.atime, 'unixepoch') AS accessed,
  (f.btime - f.ctime) / 86400 AS btime_ctime_days_diff,
  (p.start_time - f.atime) / 86400 AS start_atime_days_diff,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  hash.sha256 AS sha256,
  signature.identifier,
  signature.authority
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE
  p.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      path NOT LIKE '/System/%'
      AND path NOT LIKE '/Library/Apple/%'
      AND path NOT LIKE '/usr/libexec/%'
      AND path NOT LIKE '/usr/sbin/%'
      AND path NOT LIKE '/sbin/%'
      AND path NOT LIKE '/Volumes/%'
      AND path NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
      AND path NOT LIKE '/Applications/%/Contents/MacOS/%'
      AND path NOT LIKE '/opt/%/bin/%'
      AND path NOT LIKE '/usr/bin/%'
      AND path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
      AND path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/Kolide.app/Contents/MacOS/launcher'
  )
  AND f.btime == f.mtime
  AND (
    -- change time is older than birth time
    btime_ctime_days_diff > 0 -- change time is older than birth time, but not 1970
    OR (
      (btime_ctime_days_diff < -365)
      AND (btime_ctime_days_diff < -1000)
    ) -- access time is older than start time
    OR start_atime_days_diff > 90
  ) -- Vendors that create software packages that look like a touched file.
  AND NOT signature.authority IN (
    'Apple Mac OS Application Signing',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    'Developer ID Application: Bryan Jones (49EYHPJ4Q3)',
    'Developer ID Application: CodeWeavers Inc. (9C6B7X7Z8E)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Emmanouil Konstantinidis (3YP8SXP3BF)',
    'Developer ID Application: Fumihiko Takayama (G43BCU2T37)',
    -- Karibiner
    'Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'Developer ID Application: Galvanix (5BRAQAFB8B)',
    'Developer ID Application: General Arcade (Pte. Ltd.) (S8JLSG5ES7)',
    'Developer ID Application: GitHub (VEKTX9H2N7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Michael Jones (YD6LEYT6WZ)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    'Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
    'Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    'Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)',
    'Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    'Developer ID Application: Yubico Limited (LQA3CS5MM7)',
    'Developer ID Application: Zoom Video Communications, Inc.',
    'Software Signing'
  )
  AND NOT (
    p.euid > 500
    AND (
      p.path IN (
        '/Applications/Canon Utilities/IJ Scan Utility/Canon IJ Scan Utility Lite.app/Contents/Library/LoginItems/CIJSULAgent.app/Contents/MacOS/CIJSULAgent',
        '/Applications/Canon Utilities/Inkjet Extended Survey Program/Inkjet Extended Survey Program.app/Contents/MacOS/ESPController.app/Contents/Library/LoginItems/CanonIJExtendedSurveyLaunchAgent.app/Contents/MacOS/CanonIJExtendedSurveyLaunchAgent',
        '/Applications/Divvy.app/Contents/MacOS/Divvy',
        '/opt/homebrew/share/google-cloud-sdk/bin/log-streaming',
        '/usr/local/bin/node',
        '/Applications/Sourcetree.app/Contents/MacOS/Sourcetree',
        '/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant',
        '/Library/Printers/Brother/Utilities/BrStatusMonitor.app/Contents/MacOS/BrStatusMonitor'
      )
      OR p.path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/%'
      OR p.path LIKE '/private/var/folders/%/T/AppTranslocation/%/Contents/MacOS/%'
      OR p.path LIKE '/Applications/%.app/Contents/MacOS/%'
      OR p.path LIKE '/Applications/%.app/Contents/Frameworks/%/Versions/A/Resources/%'
      OR p.path LIKE '/opt/homebrew/Cellar/%/bin/%'
      OR p.path LIKE '/opt/homebrew/Caskroom/%/bin/%'
      OR p.path LIKE '/Users/%/google-cloud-sdk/bin/%'
      OR p.path LIKE '/Users/%/J8RPQ294UB.com.skitch.SkitchHelper'
    )
  )
  AND NOT (
    p.euid > 300
    AND p.path LIKE '/nix/store/%'
  )
  AND NOT (
    p.euid > 300 -- Electron
    AND p.path LIKE '% Helper'
  )
  AND NOT (
    p.euid = 0
    AND (
      p.path LIKE '/nix/store/%/bin/nix'
      OR p.path LIKE '/nix/store/%/bin/nix-daemon'
    )
  )
GROUP by
  p.pid
