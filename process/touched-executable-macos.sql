-- Programs which appear to have been touched on macOS
SELECT p.path,
  p.name,
  p.cmdline,
  p.euid,
  DATETIME(f.ctime, "unixepoch") AS changed,
  DATETIME(f.btime, "unixepoch") AS birthed,
  DATETIME(f.mtime, "unixepoch") AS modified,
  DATETIME(f.atime, "unixepoch") AS accessed,
  (f.btime - f.ctime) / 86400 AS btime_ctime_days_diff,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  hash.sha256 AS sha256,
  signature.identifier,
  signature.authority
FROM processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE f.btime == f.mtime
  AND (
    -- The program was touched to look newer
    btime_ctime_days_diff > 0 -- The program was touched to look older
    OR btime_ctime_days_diff < -90
  )
  AND NOT signature.authority IN (
    "Developer ID Application: Logitech Inc. (QED4VVPZWA)",
    "Developer ID Application: Bryan Jones (49EYHPJ4Q3)",
    "Developer ID Application: RescueTime, Inc (FSY4RB8H39)",
    "Developer ID Application: Michael Jones (YD6LEYT6WZ)",
    "Developer ID Application: General Arcade (Pte. Ltd.) (S8JLSG5ES7)",
    "Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)",
    "Developer ID Application: Emmanouil Konstantinidis (3YP8SXP3BF)",
    "Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)",
    "Apple Mac OS Application Signing"
  )
  AND NOT (
    btime_ctime_days_diff < -90
    AND p.euid > 500
    AND (
      p.path IN (
        "/Applications/Divvy.app/Contents/MacOS/Divvy",
        "/Applications/Sourcetree.app/Contents/MacOS/Sourcetree",
        "/Library/CoreMediaIO/Plug-Ins/DAL/LogiCapture.plugin/Contents/MacOS/Assistant",
        "/Applications/Canon Utilities/IJ Scan Utility/Canon IJ Scan Utility Lite.app/Contents/Library/LoginItems/CIJSULAgent.app/Contents/MacOS/CIJSULAgent",
        "/Applications/Canon Utilities/Inkjet Extended Survey Program/Inkjet Extended Survey Program.app/Contents/MacOS/ESPController.app/Contents/Library/LoginItems/CanonIJExtendedSurveyLaunchAgent.app/Contents/MacOS/CanonIJExtendedSurveyLaunchAgent"
      )
      OR p.path LIKE "/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/%"
      OR p.path LIKE "/opt/homebrew/Cellar/bash/%/bin/bash"
    )
  )
GROUP by p.pid