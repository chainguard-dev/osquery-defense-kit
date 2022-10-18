-- Unusually small programs (events-based)
--
-- references:
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- interval: 30
-- tags: transient process events
SELECT
  p.pid,
  p.path,
  p.cmdline,
  file.size,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  p.syscall,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  process_events p
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  p.time > (strftime('%s', 'now') -30)
  AND file.size > 0
  AND file.size < 10000
  AND p.path NOT LIKE '%.sh'
  AND p.path NOT LIKE '%.py'
  AND p.path NOT LIKE '%.rb'
  -- Removes a false-positive we've seen on Linux, generated through 'runc init'
  AND NOT (
    p.path = "/"
    AND file.size < 8192
  )
