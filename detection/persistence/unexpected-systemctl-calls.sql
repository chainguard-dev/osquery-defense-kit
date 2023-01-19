-- Suspicious calls to systemctl(event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1543/002/ (Create or Modify System Process: Systemd Service)
--
-- tags: transient process state often
-- platform: linux
-- interval: 900
SELECT
  pe.path AS child_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS child_name,
  TRIM(pe.cmdline) AS child_cmd,
  pe.pid AS child_pid,
  p.cgroup_path AS child_cgroup,
  pe.parent AS parent_pid,
  TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
  TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
  IIF(pp.path != NULL, phash.sha256, pehash.sha256) AS parent_hash,
  REGEX_MATCH (
    IIF(pp.path != NULL, pp.path, ppe.path),
    '.*/(.*)',
    1
  ) AS parent_name,
  TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
  TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
  IIF(gp.path != NULL, gphash.sha256, gpehash.path) AS gparent_hash,
  REGEX_MATCH (
    IIF(gp.path != NULL, gp.path, gpe.path),
    '.*/(.*)',
    1
  ) AS gparent_name,
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid,
  CONCAT (
    REGEX_MATCH (pe.path, '.*/(.*)', 1),
    ',',
    MIN(pe.euid, 500),
    ',',
    REGEX_MATCH (
      IIF(pp.path != NULL, pp.path, ppe.path),
      '.*/(.*)',
      1
    ),
    ',',
    REGEX_MATCH (
      IIF(gp.path != NULL, gp.path, gpe.path),
      '.*/(.*)',
      1
    )
  ) AS exception_key
FROM
  process_events pe, uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN hash phash ON pp.path = phash.path
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN hash pehash ON ppe.path = pehash.path
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN hash gphash ON gp.path = gphash.path
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash gpehash ON gpe.path = gpehash.path
WHERE
  uptime.total_seconds > 30
  -- NOTE: The remainder of this query is synced with unexpected-fetcher-parents
  AND pe.path IN (
    '/usr/bin/systemctl',
    '/bin/systemctl',
    '/sbin/systemctl'
  )
  AND pe.time > (strftime('%s', 'now') -29000) -- Ignore partial table joins
GROUP BY
  pe.pid
