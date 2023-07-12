-- Find root-run processes which link against libpcap
--
-- references:
--   * https://attack.mitre.org/techniques/T1205/001/ (Traffic Signaling: Port Knocking)
--
-- platform: darwin
-- tags: persistent state process sniffer
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
  p0.pid IN (
    SELECT pid FROM processes WHERE
      euid = 0
      AND path NOT LIKE '/System/%'
      AND path NOT LIKE '/Library/Apple/%'
      AND path NOT LIKE '/usr/libexec/%'
      AND path NOT LIKE '/usr/sbin/%'
      AND path NOT LIKE '/sbin/%'
      AND path NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
      AND path NOT LIKE '/usr/bin/%'
      AND path NOT LIKE '/nix/store/%/bin/nix'
      AND path NOT LIKE '/opt/homebrew/Cellar/vim/%/bin/vim'
      AND path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
      AND path NOT LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/Kolide.app/Contents/MacOS/launcher'
      AND path NOT LIKE '/opt/homebrew/Cellar/socket_vmnet/%/bin/socket_vmnet'
      AND path NOT LIKE '/usr/local/Cellar/htop/%/bin/htop'
      AND path NOT LIKE '/opt/homebrew/Cellar/btop/%/bin/btop'
      AND path NOT IN ('/opt/socket_vmnet/bin/socket_vmnet', '/usr/local/sbin/velociraptor')
  )

  AND pmm.path LIKE '%libpcap%'
  -- These are all protected directories
  AND NOT s.authority IN (
    'Software Signing',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Apple Mac OS Application Signing',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)'
  )
GROUP BY
  p0.pid
