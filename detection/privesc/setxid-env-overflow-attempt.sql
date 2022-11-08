-- Find setuid process events with large environment sizes
--
-- ******************************************************************
-- NOTE: This is a rare case of a non-working query. It does not work
-- in my environment (osquery 5.5.1 running with Kolide) as
-- process_events.env_size is NULL. I believe this to be a bug, but
-- requires more investigation.
-- ******************************************************************
--
-- tags: events process escalation disabled seldom
-- platform: posix
--
-- Uncomment once the underlying problem is addressed:
-- XintervalX: 60
SELECT
  p.pid AS child_pid,
  p.path AS child_path,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*/(.*?)$', 1) AS child_name,
  p.cmdline AS child_cmdline,
  p.euid AS child_euid,
  file.mode AS child_mode,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmdline,
  p.env,
  p.env_size
FROM
  process_events p
  JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN file AS pfile ON pp.path = pfile.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  p.time > (strftime('%s', 'now') -60)
  AND file.mode NOT LIKE '0%'
  AND p.env_size > 3500
