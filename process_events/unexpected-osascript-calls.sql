-- Detect unusual calls to osascript
-- Designed for execution every 15 seconds (where the parent may still be around)
SELECT p.pid,
  p.path,
  TRIM(p.cmdline) AS cmd,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  p.syscall,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  TRIM(p.cmdline) AS parent_cmd,
  pp.euid AS parent_euid,
  phash.sha256 AS parent_sha256
FROM uptime,
  process_events p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = hash.path
WHERE p.path = "/usr/bin/osascript"
  AND p.time > (strftime('%s', 'now') -1800)