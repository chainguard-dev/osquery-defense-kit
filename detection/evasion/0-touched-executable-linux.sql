-- Programs which were spawned by an executable containing a matching ctime & mtime, which
-- on Linux only generally occurs occurs if you run 'touch <bin>'
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Timestomping)
--
-- tags: transient process state extra
-- platform: linux
SELECT
  p.pid,
  p.path,
  p.name,
  p.cmdline,
  p.cgroup_path,
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
  AND (strftime('%s', 'now') - p.start_time) > 25000
  AND p.path != '/'
  AND f.path NOT IN (
    '/opt/Elastic/Endpoint/elastic-endpoint',
    '/opt/google/endpoint-verification/bin/apihelper',
    '/opt/resolve/bin/resolve',
    '/usr/bin/ld.bfd',
    '/usr/bin/ld',
    '/usr/bin/ghostty',
    '/usr/bin/melange',
    '/var/opt/velociraptor/bin/velociraptor'
  )
  AND f.path NOT LIKE '/home/%'
  AND f.path NOT LIKE '/opt/Elastic/Agent/data/elastic-agent%'
  AND f.path NOT LIKE '/opt/rapid7/ir_agent/%'
  AND f.path NOT LIKE '/snap/%'
  AND f.path NOT LIKE '/tmp/%/.terraform/providers/%'
  AND f.path NOT LIKE '/tmp/%go-build%/exe/%'
  AND f.path NOT LIKE '/tmp/cargo-install%/%'
  AND f.path NOT LIKE '/tmp/go-build%'
  AND f.path NOT LIKE '/usr/local/aws-cli/%/dist/aws'
  AND f.path NOT LIKE '/usr/local/bin/%'
  AND f.path NOT LIKE '/usr/local/kolide-k2/bin/%-updates/%'
  AND f.path NOT LIKe '/var/home/%'
  AND f.path NOT LIKE '/var/home/linuxbrew/.linuxbrew/%'
  AND f.path NOT LIKE '/var/home/linuxbrew/.linuxbrew/Cellar/%/bin/%'
  AND f.path NOT LIKE '/var/kolide-k2/k2device.kolide.com/updates/%'
  AND f.path NOT LIKE '/var/opt/Elastic/Endpoint/elastic-endpoint'
  AND f.path NOT LIKE '%/go/bin/%'
  AND f.path NOT LIKE '%/osqueryi'
  AND p.name NOT LIKE 'osqtool%'
GROUP by
  p.pid
