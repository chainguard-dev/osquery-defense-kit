-- Find root-run processes which link against libpcap
--
-- WARNING: This check consumes an unusual amount of system memory (up to 225MB)
--
-- references:
--   * https://attack.mitre.org/techniques/T1205/001/ (Traffic Signaling: Port Knocking)
--
-- platform: linux
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
  ph.sha256 AS parent_sha256
FROM
  process_memory_map pmm
  LEFT JOIN processes p ON pmm.pid = p.pid
  LEFT JOIN hash h ON p.path = h.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash AS ph ON pp.path = ph.path
WHERE
  pmm.path LIKE '%libpcap%'
  AND p.euid = 0
  AND child_path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND child_path NOT LIKE '/nix/store/%-systemd-%/lib/systemd/systemd%'
  AND child_path NOT LIKE '/nix/store/%-systemd-%/bin/udevadm'
  AND child_path NOT LIKE '/System/Library/%'
  AND child_path NOT LIKE '/nix/store/%/bin/nix'
  AND child_path NOT IN (
    '/usr/libexec/UserEventAgent',
    '/usr/sbin/systemstats',
    '/usr/bin/libvirtd',
    '/usr/sbin/cupsd',
    '/run/current-system/systemd/lib/systemd/systemd'
  )
  AND child_cmd NOT IN (
    '/nix/var/nix/profiles/default/bin/nix-daemon',
    '/run/current-system/systemd/lib/systemd/systemd',
    '/usr/bin/python3 -s /usr/sbin/firewalld --nofork --nopid'
  )
GROUP BY
  pmm.pid
