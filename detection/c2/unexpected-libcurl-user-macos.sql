-- Find programs processes which link against libcurl, common among cross-platform malware
--
-- References:
--  * https://objective-see.org/blog/blog_0x6C.html
--  * https://objective-see.org/blog/blog_0x72.html
--
-- platform: darwin
-- tags: persistent state process seldom
SELECT
  s.authority,
  s.identifier,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  JOIN process_memory_map pmm ON p0.pid = pmm.pid
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.euid = 0
  AND pmm.path LIKE '%libcurl%'
  AND p0.name NOT IN ('nix-daemon', 'nix')
GROUP BY
  p0.pid
