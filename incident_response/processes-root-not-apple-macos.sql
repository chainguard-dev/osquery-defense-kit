-- Programs running as root from unusual signers on macOS
--
-- platform: darwin
-- tags: transient process
-- Canonical example of including process parents from process_events
SELECT
  p.*,
  s.*
FROM
  processes p
  LEFT JOIN signature s ON p.path = s.path
WHERE
  p.pid IN (
    SELECT pid FROM processes WHERE
    p.euid = 0
    AND p.path NOT LIKE "/System/%"
    AND p.path NOT LIKE "/Library/Apple/%"
    AND p.path NOT LIKE "/usr/bin/%"
    AND p.path NOT LIKE "/usr/libexec/%"
    AND p.path NOT LIKE "/usr/sbin/%"
  )
  AND s.authority NOT IN ('Software Signing')