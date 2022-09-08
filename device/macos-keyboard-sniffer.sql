SELECT et.*, p.path, s.authority, s.identifier
FROM event_taps et
JOIN processes p ON et.tapping_process = p.pid
JOIN signature s ON s.path = p.path
WHERE event_tapped IN ('EventKeyDown', 'EventKeyUp')
AND authority != "Software Signing"
AND NOT (identifier='com.googlecode.iterm2' AND authority='Developer ID Application: GEORGE NACHMAN (H7V7XYVQ7D)')
GROUP BY p.path
