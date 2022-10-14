-- Find programs that are sniffing keyboard events on macOS
--
-- references:
--   * https://attack.mitre.org/techniques/T1056/001/ (Input Capture: Keylogging)
--
-- platform: darwin
-- tags: persistent state sniffer
SELECT
  et.enabled,
  et.process_being_tapped,
  et.tapping_process,
  p.path,
  s.authority,
  s.identifier,
  h.sha256,
  CONCAT (
    REPLACE(
      p.path,
      RTRIM(p.path, REPLACE(p.path, '/', '')),
      ''
    ),
    ',',
    identifier,
    ',',
    authority
  ) AS exception_key
FROM
  event_taps et
  LEFT JOIN processes p ON et.tapping_process = p.pid
  LEFT JOIN signature s ON s.path = p.path
  LEFT JOIN hash h ON h.path = p.path
WHERE
  event_tapped IN ('EventKeyDown', 'EventKeyUp')
  AND authority != 'Software Signing'
  AND NOT exception_key IN (
    'BetterTouchTool,com.hegenberg.BetterTouchTool,Developer ID Application: folivora.AI GmbH (DAFVSXZ82P)',
    'iTerm2,com.googlecode.iterm2,Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'lghub_agent,com.logi.ghub.agent,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'logioptionsplus_agent,com.logi.cp-dev-mgr,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'MonitorControl,me.guillaumeb.MonitorControl,Developer ID Application: Joni Van Roost (CYC8C8R4K9)',
    'skhd,skhd,'
  )
GROUP BY
  p.path
