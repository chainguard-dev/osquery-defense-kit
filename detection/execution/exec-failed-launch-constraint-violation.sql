-- Catch programs that failed to run due to a launch constraint violation, such as a signing issue.
--
-- references:
--   * https://attack.mitre.org/techniques/T1204/
--
-- interval: 900
-- platform: darwin
-- tags: filesystem events
SELECT
  -- Child
  pe.path AS p0_path,
  s.authority AS p0_sauth,
  s.identifier AS p0_sid,
  hash.sha256 AS p0_hash,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.time AS p0_time,
  p.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.euid AS p0_euid,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  p1.cwd AS p1_cwd,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  p1_p2.cwd AS p2_cwd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name
FROM
  process_events pe
  LEFT JOIN signature s ON pe.path = s.path
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN hash ON pe.path = hash.path
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
WHERE
  pe.time > (strftime('%s', 'now') -900)
  AND pe.status = 1
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND p0_cmd != '/opt/homebrew/opt/tailscale/bin/tailscaled'
GROUP BY
  pe.euid,
  pe.path,
  pe.cmdline
