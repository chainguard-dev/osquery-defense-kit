-- Programs which claim to be from the future, based on (btime,ctime,mtime)
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Indicator Removal on Host: Timestomp)
--
-- false positives:
--   * None observed
--
-- tags: persistent state process
SELECT
  p.pid,
  p.path,
  p.name,
  p.cmdline,
  p.cwd,
  p.euid,
  p.parent,
  f.ctime,
  f.btime,
  f.mtime,
  p.start_time,
  f.mtime > strftime('%s', 'now') AS mtime_newer,
  f.ctime > strftime('%s', 'now') AS ctime_newer,
  f.btime > strftime('%s', 'now') AS btime_newer,
  hash.sha256 AS child_hash256,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  mtime_newer == 1
  OR ctime_newer == 1
  OR btime_newer == 1
