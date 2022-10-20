-- Unexpected programs speaking over ICMP (event-based)
--
-- references:
--   *https://attack.mitre.org/techniques/T1095/ (C2: Non-Application Layer Protocol)
--
-- interval: 30
-- tags: transient events net
SELECT
  se.*,
  p.path,
  p.cmdline
FROM
  socket_events se
  LEFT JOIN processes p ON se.pid = p.pid
WHERE
  se.time > (strftime('%s', 'now') -30)
  AND family = 2 -- PF_INET
  AND protocol = 1 -- ICMP
  AND p.name NOT IN ('ping')
