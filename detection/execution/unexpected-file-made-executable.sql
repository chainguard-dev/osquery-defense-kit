-- Detect commands used to bless a file as executable
--
-- false positives:
--   * none observed, but they are expected
--
-- interval: 600
-- platform: posix
-- tags: process events
SELECT pe.path AS path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS name,
  TRIM(pe.cmdline) AS cmd,
  pe.pid AS pid,
  pe.euid AS euid,
  pe.parent AS parent_pid,
  TRIM(IIF(pp.cmdline != NULL, pp.cmdline, ppe.cmdline)) AS parent_cmd,
  TRIM(IIF(pp.path != NULL, pp.path, ppe.path)) AS parent_path,
  REGEX_MATCH (
    IIF(pp.path != NULL, pp.path, ppe.path),
    '.*/(.*)',
    1
  ) AS parent_name,
  TRIM(IIF(pp.path != NULL, hash.sha256, ehash.sha256)) AS parent_hash,
  pp.cgroup_path AS parent_cgroup,
  TRIM(IIF(gp.cmdline != NULL, gp.cmdline, gpe.cmdline)) AS gparent_cmd,
  TRIM(IIF(gp.path != NULL, gp.path, gpe.path)) AS gparent_path,
  REGEX_MATCH (
    IIF(gp.path != NULL, gp.path, gpe.path),
    '.*/(.*)',
    1
  ) AS gparent_name,
  IIF(pp.parent != NULL, pp.parent, ppe.parent) AS gparent_pid,
  REGEX_MATCH(TRIM(pe.cmdline), ".* (.*?)$", 1) AS target_path
FROM process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN process_events ppe ON pe.parent = ppe.pid
  LEFT JOIN processes gp ON gp.pid = pp.parent
  LEFT JOIN process_events gpe ON ppe.parent = gpe.pid
  LEFT JOIN hash ON pp.path = hash.path
  LEFT JOIN hash thash ON target_path = thash.path
  LEFT JOIN hash ehash ON ppe.path = ehash.path
WHERE pe.time > (strftime('%s', 'now') -600)
AND pe.path LIKE '%/chmod'
AND (
  cmd LIKE '%chmod 7%'
  OR cmd LIKE '%chmod 5%'
  OR cmd LIKE '%chmod 1%'
  OR cmd LIKE '%chmod +%x'
)
AND NOT (
  cmd LIKE 'chmod 700 /tmp/apt-key-gpghome.%'
  OR cmd like 'chmod 700 /home/%/snap/firefox/%/.config'
  OR cmd = 'chmod 755 /usr/local/share/ca-certificates'
)
AND NOT parent_cgroup LIKE '/system.slice/docker-%'
GROUP BY pe.pid
