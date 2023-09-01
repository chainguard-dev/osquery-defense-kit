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
  CONCAT (
    REPLACE(
      p0.path,
      RTRIM(p0.path, REPLACE(p0.path, '/', '')),
      ''
    ),
    ',',
    s.identifier,
    ',',
    s.authority
  ) AS exception_key,
  ---
  s.authority,
  s.identifier,
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
  event_taps et
  LEFT JOIN processes p0 ON et.tapping_process = p0.pid
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  et.event_tapped IN ('EventKeyDown', 'EventKeyUp')
  AND s.authority != 'Software Signing' -- Popular programs that sniff keyboard events, but do not appear to be malware.
  AND NOT exception_key IN (
    'BetterTouchTool,com.hegenberg.BetterTouchTool,Developer ID Application: folivora.AI GmbH (DAFVSXZ82P)',
    'Contexts,com.contextsformac.Contexts,Developer ID Application: Usman Khalid (RZ7E748ZSC)',
    'Hyperkey,com.knollsoft.Hyperkey,Developer ID Application: Ryan Hanson (XSYZ3E4B7D)',
    'iTerm2,com.googlecode.iterm2,Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)',
    'lghub_agent,com.logi.ghub.agent,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'logioptionsplus_agent,com.logi.cp-dev-mgr,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'MonitorControl,me.guillaumeb.MonitorControl,Developer ID Application: Joni Van Roost (CYC8C8R4K9)',
    'osqueryd,io.osquery.agent,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Rocket,net.matthewpalmer.Rocket,Developer ID Application: Matthew Palmer (Z4JV2M65MH)',
    'skhd,skhd,',
    'synergy-core,synergy-core,Developer ID Application: Symless Ltd (4HX897Y6GJ)',
    'TextExpander,com.smileonmymac.textexpander,Developer ID Application: SmileOnMyMac, LLC (7PKJ6G4DXL)'
  )
GROUP BY
  p0.path
