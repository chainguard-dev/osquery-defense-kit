-- Programs which were spawned by an executable containing a matching ctime & mtime, which
-- on Linux only generally occurs occurs if you run 'touch <bin>'
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Timestomping)
--
-- tags: transient process state
-- platform: linux
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
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  hash.sha256 AS sha256
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  f.ctime = f.mtime
  AND p.path != '/'
  AND f.path NOT LIKE '/usr/local/kolide-k2/bin/%-updates/%'
  AND f.path NOT LIKE '/snap/%'
  AND f.path NOT LIKE '/home/%'
  AND f.path != '/usr/local/bin/chainctl'
  AND f.path NOT LIKE '/tmp/go-build%/exe/main'
GROUP by
  p.pid
