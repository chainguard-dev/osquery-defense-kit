-- Unusually small programs (events-based)
--
-- references:
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- interval: 300
-- tags: transient process events
SELECT
  p.pid,
  p.path,
  p.cmdline,
  file.size,
  p.time,
  file.type,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  p.syscall,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256,
  magic.data AS magic
FROM
  process_events p
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash phash ON pp.path = phash.path
  LEFT JOIN magic ON p.path = magic.path
WHERE
  p.time > (strftime('%s', 'now') -300)
  AND file.size > 0
  AND file.size < 10000
  AND file.type = 'regular'
  AND p.cwd != ""
  AND p.cwd IS NOT NULL
  AND p.path NOT LIKE '%.sh'
  AND p.path NOT LIKE '%.py'
  AND p.path NOT LIKE '%.rb'
  AND p.path != '/sbin/ldconfig'
  AND NOT (
    p.path LIKE '/Users/%'
    AND magic.data LIKE 'POSIX shell script%'
  )
  AND p.path NOT LIKE '/private/var/folders/%/T/iTerm2-scrip%sh'
  AND p.path NOT LIKE '/home/%/.local/share/Steam/%'
  AND p.path NOT LIKE '%/openoffice%/program/pagein'
  -- Removes a false-positive we've seen on Linux, generated through 'runc init'
  AND NOT (
    p.path = "/"
    AND file.size < 8192
  )
