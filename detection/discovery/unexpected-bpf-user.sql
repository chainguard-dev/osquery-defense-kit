-- Find root-run processes which link against libpf
--
-- WARNING: This check consumes an unusual amount of system memory (up to 225MB)
--
-- references:
--   * https://attack.mitre.org/techniques/T1205/001/ (Traffic Signaling: Port Knocking)
--
-- platform: posix
-- tags: persistent state process sniffer
SELECT
  pmm.pid,
  pmm.path AS lib_path,
  p.path,
  p.name,
  p.cmdline,
  p.cwd,
  p.euid,
  p.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256
FROM
  process_memory_map pmm
  LEFT JOIN processes p ON pmm.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  (
    lib_path LIKE '%:bpf%'
    OR lib_path LIKE '%libbpf%'
  )
  AND p.path NOT IN (
    '/usr/bin/qemu-system-x86_64',
    '/usr/lib/systemd/systemd'
  )
  AND p.path NOT LIKE '/nix/store/%/lib/systemd/systemd'
GROUP BY
  pmm.pid
