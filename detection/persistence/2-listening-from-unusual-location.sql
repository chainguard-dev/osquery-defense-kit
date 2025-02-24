-- Unexpected programs listening from /tmp or other weird directories
--
--
-- tags: persistent state net often
-- Canonical example of information to include for processes
SELECT
  lp.address,
  lp.port,
  lp.protocol,
  REPLACE(f.directory, u.directory, '~') AS homepath,
  REPLACE(p0.cwd, u.directory, '~') AS homecwd,
  CONCAT (
    MIN(lp.port, 32768),
    ',',
    lp.protocol,
    ',',
    MIN(p0.uid, 500),
    ',',
    p0.name
  ) AS exception_key,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.start_time AS p0_start,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.start_time AS p1_start,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.start_time AS p2_start,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  listening_ports lp
  JOIN processes p0 ON lp.pid = p0.pid
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN users u ON f.uid = u.uid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  lp.port != 0
  AND NOT lp.address IN ("127.0.0.1", "::1")
  AND (
    p0.path LIKE "/private/tmp%"
    OR p0.path LIKE "/private/var/tmp%"
    OR p0.path LIKE "/var/tmp%"
    OR p0.path LIKE "/tmp%"
    OR p0.path LIKE "/dev%"
    OR p0.path LIKE "/Users/Shared%"
    OR p0.path LIKE "%/.%"
    OR p0.cwd LIKE "/private/tmp%"
    OR p0.cwd LIKE "/private/var/tmp%"
    OR p0.cwd LIKE "/var/tmp%"
    OR p0.cwd LIKE "/tmp%"
    OR p0.cwd LIKE "/dev%"
    OR p0.cwd LIKE "%/.%"
    OR p0.cwd LIKE "/Users/Shared%"
  )
  AND NOT (
    p0.name IN (
      'aws',
      'caddy',
      'controller',
      'crane',
      'docker-proxy',
      'gopls',
      'hugo',
      'kubectl',
      'limactl',
      'nginx-ingress-c',
      'node',
      'nuclei',
      'ollama',
      'ping',
      'qemu-system-aarch64',
      'qemu-system-x86',
      'rootlessport',
      'webhook'
    )
    AND lp.port > 1024
    and lp.protocol = 6
  )
  -- Overly broad, but prevents a lot of false positives
  AND NOT homepath LIKE "~/.%"
  AND NOT homecwd LIKE "~/.%"
  AND NOT homecwd LIKE "~/src/%"
  AND NOT homecwd LIKE "~/repos/%"
  AND NOT homecwd LIKE '/Users/%/.gradle/daemon/%'
  AND NOT homecwd LIKE '/home/%/.gradle/daemon/%'
  AND NOT f.directory IN (
    '/Applications/Keybase.app/Contents/SharedSupport/bin',
    '/opt/docker-desktop/bin'
  )
  AND NOT exception_key IN (
    '16620,6,500,psi-bastion',
    '2112,6,500,rebuilder',
    '32768,6,500,java',
    '32768,6,500,logioptionsplus_agent',
    '32768,17,500,logioptionsplus_agent',
    '32768,6,500,Chromium',
    '32768,6,500,Code Helper (Plugin)',
    '24024,17,500,MTGA',
    '32768,6,500,Python',
    '32768,6,500,python3',
    '32768,17,499,viscosity_openvpn',
    '9867,6,500,bazel-remote',
    '1,1,500,ping'
  )
  AND NOT p0.path LIKE '/nix/store/%'
  AND NOT p0.path LIKE '/Users/Shared/Epic Games/%'
  AND NOT p0.path LIKE '/tmp/go-build%'
  AND NOT (
    exception_key = '32768,17,500,qemu-system-x86'
    AND homecwd LIKE '/tmp/wolfi-%'
  )
  AND NOT (
    exception_key = '32768,17,500,go'
    AND homecwd LIKE '%/.terraform/modules/%'
  )
