-- Unexpected programs speaking over ICMP (state-based)
--
-- references:
--   *https://attack.mitre.org/techniques/T1095/ (C2: Non-Application Layer Protocol)
--
-- tags: transient state net often
SELECT
  pop.pid AS p0_pid,
  pop.socket,
  pop.local_address,
  pop.remote_address,
  -- Child
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  process_open_sockets pop
  LEFT JOIN processes p0 ON pop.pid = p0.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  pop.family = 2 -- PF_INET
  AND pop.protocol = 1 -- ICMP
  AND p0.name NOT IN ('ping')
GROUP BY
  p0_pid
