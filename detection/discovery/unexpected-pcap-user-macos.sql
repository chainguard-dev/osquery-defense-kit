-- Find root-run processes which link against libpcap
--
-- WARNING: This check consumes an unusual amount of system memory (up to 225MB)
--
-- references:
--   * https://attack.mitre.org/techniques/T1205/001/ (Traffic Signaling: Port Knocking)
--
-- platform: darwin
-- tags: persistent state process sniffer
SELECT
  pmm.pid,
  p.uid,
  p.gid,
  pmm.path AS lib_path,
  p.path AS child_path,
  p.name AS child_name,
  p.cmdline AS child_cmd,
  p.cwd AS child_cwd,
  h.sha256 AS child_sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  ph.sha256 AS parent_sha256,
  s.authority,
  s.identifier
FROM
  process_memory_map pmm
  LEFT JOIN processes p ON pmm.pid = p.pid
  LEFT JOIN hash h ON p.path = h.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash AS ph ON pp.path = ph.path
  LEFT JOIN signature s ON p.path = s.path
WHERE
  pmm.path LIKE '%libpcap%'
  AND p.euid = 0 -- These are all protected directories
  AND child_path NOT LIKE '/System/%'
  AND child_path NOT LIKE '/usr/libexec/%'
  AND child_path NOT LIKE '/usr/sbin/%'
  AND child_path NOT LIKE '/usr/bin/%'
  AND child_path NOT LIKE '/nix/store/%/bin/nix'
  AND child_path NOT LIKE '/opt/homebrew/Cellar/vim/%/bin/vim'
  AND child_path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND NOT s.authority IN (
    'Software Signing',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)'
  )
GROUP BY
  pmm.pid
