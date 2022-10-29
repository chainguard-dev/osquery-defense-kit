-- Find setuid events with large cmdlines
--
-- platform: posix
-- interval: 60
SELECT
  p.pid AS child_pid,
  p.path AS child_path,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*/(.*?)$', 1) AS child_name,
  p.cmdline AS child_cmdline,
  p.auid AS child_auid,
  p.euid AS child_euid,
  file.mode AS child_mode,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmdline,
  p.cmdline_size
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
  AND p.cmdline_size > 1024
