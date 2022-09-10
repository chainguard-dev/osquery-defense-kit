SELECT et.*, p.path, s.authority, s.identifier, h.sha256
FROM event_taps et
JOIN processes p ON et.tapping_process = p.pid
JOIN signature s ON s.path = p.path
JOIN hash h ON h.path = p.path
WHERE event_tapped IN ('EventKeyDown', 'EventKeyUp')
AND authority != "Software Signing"
AND NOT (identifier='com.googlecode.iterm2' AND authority='Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)')
AND NOT (identifier='skhd' AND p.path LIKE '/opt/homebrew/Cellar/%/bin/skhd')
AND NOT (identifier='com.logi.ghub.agent' AND p.path = '/Applications/lghub.app/Contents/Frameworks/lghub_agent.app/Contents/MacOS/lghub_agent')
GROUP BY p.path
