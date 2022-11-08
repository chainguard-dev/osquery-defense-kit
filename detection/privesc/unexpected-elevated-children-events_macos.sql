-- Find processes that run with a lower effective UID than their parent (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1548/001/ (Setuid and Setgid)
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- related:
--   * unexpected-privilege-escalation.sql
--
-- tags: events process escalation
-- platform: darwin
-- interval: 30
SELECT
  p.pid AS child_pid,
  p.path AS child_path,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*/(.*?)$', 1) AS child_name,
  p.cmdline AS child_cmdline,
  p.time,
  pp.start_time,
  p.euid AS child_euid,
  file.mode AS child_mode,
  hash.sha256 AS child_hash,
  p.parent AS parent_pid,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  pfile.mode AS parent_mode,
  phash.sha256 AS parent_hash
FROM
  process_events p
  JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN file AS pfile ON pp.path = pfile.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  p.time > (strftime('%s', 'now') -30)
  AND p.euid < pp.euid
  AND p.path NOT IN (
    '/usr/bin/login',
    '/usr/bin/su',
    '/usr/bin/sudo',
    '/usr/local/bin/doas'
  )
