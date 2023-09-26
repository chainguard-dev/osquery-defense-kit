-- Unexpected programs listening on a TCP port (state-based).
--
-- references:
--   * https://attack.mitre.org/techniques/T1571/ (Non-Standard Port)
--
-- tags: persistent state net
SELECT
  lp.address,
  lp.port,
  lp.protocol,
  p.euid,
  p.cgroup_path,
  p.parent,
  p.pid,
  p.name,
  p.path,
  p.cmdline AS p0_cmd,
  p_p.cmdline AS p1_cmd,
  p_p_p.cmdline AS p2_cmd,
  p.cgroup_path,
  datetime(file.mtime, 'unixepoch') AS mtime,
  p.cwd,
  hash.sha256,
  CONCAT (
    MIN(lp.port, 32768),
    ',',
    lp.protocol,
    ',',
    MIN(p.uid, 500),
    ',',
    p.name
  ) AS exception_key
FROM
  listening_ports lp
  LEFT JOIN processes p ON lp.pid = p.pid
  LEFT JOIN processes p_p ON p.parent = p_p.pid
  LEFT JOIN processes p_p_p ON p_p.parent = p_p_p.pid
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN hash ON p.path = hash.path
WHERE
  port != 0
  AND lp.address NOT IN ('224.0.0.251', '::1')
  AND lp.address NOT LIKE '127.0.0.%'
  AND lp.address NOT LIKE '172.1%'
  AND lp.address NOT LIKE 'fe80::%'
  AND lp.address NOT LIKE '::ffff:127.0.0.%'
  -- All outgoing UDP (protocol 17) sessions are 'listening'
  AND NOT (
    lp.protocol = 17
    AND lp.port > 1024
  )
  -- Random webservers
  AND NOT (
    p.uid > 500
    AND lp.port IN (8000, 8080)
    AND lp.protocol = 6
  )
  -- Filter out unmapped raw sockets
  AND NOT (p.pid == '')
  -- Exceptions: the uid is capped at 500 to represent regular users versus system users
  -- port is capped at 32768 to represent transient ports
  AND NOT CONCAT (
    MIN(lp.port, 32768),
    ',',
    lp.protocol,
    ',',
    MIN(p.uid, 500),
    ',',
    p.name
  ) IN (
    '10250,6,0,kubelet',
    '10250,6,500,kubelet',
    '22,6,0,systemd',
    '58,255,500,systemd-network',
    '68,17,500,systemd-network',
    '10254,6,101,nginx-ingress-c',
    '10256,6,0,kube-proxy',
    '10256,6,500,kube-proxy',
    '1,1,500,ping',
    '1,255,500,mtr-packet',
    '1716,6,500,kdeconnectd',
    '17,255,0,dhcpcd',
    '17,255,0,tailscaled',
    '17,255,0,.tailscaled-wra',
    '17,255,500,dhcpcd',
    '17,255,500,mtr-packet',
    '18000,6,500,kourier',
    '22000,6,500,syncthing',
    '22,6,0,sshd',
    '2379,6,500,etcd',
    '2380,6,500,etcd',
    '255,255,500,mtr-packet',
    '27036,6,500,steam',
    '3000,6,472,grafana-server',
    '3000,6,500,grafana-server',
    '3000,6,500,node',
    '32768,6,0,tailscaled',
    '32768,6,500,java',
    '32768,6,0,.tailscaled-wra',
    '32768,6,500,com.docker.backend',
    '32768,6,500,dleyna-renderer',
    '32768,6,500,jetbrains-toolb',
    '32768,6,500,spotify',
    '3551,6,0,apcupsd',
    '4143,6,500,linkerd2-proxy',
    '4191,6,500,linkerd2-proxy',
    '443,6,0,docker-proxy',
    '443,6,0,tailscaled',
    '443,6,500,jcef_helper',
    '4443,6,500,metrics-server',
    '5000,6,0,registry',
    '5000,6,500,ControlCenter',
    '5001,6,0,registry',
    '5050,6,500,rootlesskit',
    '53,17,0,coredns',
    '53,17,500,aardvark-dns',
    '53,17,500,dnsmasq',
    '5355,6,193,systemd-resolve',
    '53,6,0,coredns',
    '53,6,500,dnsmasq',
    '5432,6,70,postgres',
    '546,17,500,dhcpcd',
    '5355,6,500,systemd-resolve',
    '5556,6,500,dex',
    '5556,6,500,openshot-qt',
    '5558,6,500,dex',
    '58,255,0,dhcpcd',
    '58,255,0,NetworkManager',
    '58,255,100,systemd-network',
    '58,255,500,dhcpcd',
    '58,255,500,mtr-packet',
    '631,17,0,cups-browsed',
    '6379,6,500,redis-server',
    '6443,6,0,kube-apiserver',
    '67,17,500,dnsmasq',
    '68,17,0,dhclient',
    '68,17,100,systemd-network',
    '68,17,500,dhcpcd',
    '7000,6,500,ControlCenter',
    '8008,6,500,activator',
    '8008,6,500,autoscaler',
    '8008,6,500,controlplane',
    '8008,6,500,resolvers',
    '8008,6,500,webhook',
    '8009,6,0,java',
    '80,6,0,docker-proxy',
    '80,6,101,nginx',
    '80,6,60,nginx',
    '8080,6,0,coredns',
    '8080,6,0,java',
    '8086,6,0,influxd',
    '8086,6,500,controller',
    '8086,6,500,influxd',
    '8090,6,500,linkerd-policy-',
    '8123,6,500,Brackets-node',
    '8181,6,0,coredns',
    '8443,6,0,kube-apiserver',
    '8443,6,101,nginx-ingress-c',
    '8443,6,500,controller',
    '8443,6,500,controlplane',
    '53,6,500,coredns',
    '3000,6,500,grafana',
    '8443,6,500,webhook',
    '53,17,500,coredns',
    '8081,6,500,main',
    '6443,6,500,kube-apiserver',
    '24800,6,500,synergy-core',
    '24802,6,500,synergy-service',
    '8181,6,500,coredns',
    '8834,6,0,nessusd',
    '9000,6,500,authentik-proxy',
    '9000,6,500,main',
    '8001,6,500,__debug_bin,',
    '9090,6,500,controlplane',
    '9153,6,0,coredns',
    '9300,6,500,authentik-proxy',
    '9880,6,500,rootlesskit'
  )
  AND NOT (
    p.path LIKE '/ko-app/%'
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    p.name IN (
      'caddy',
      'controller',
      'docker-proxy',
      'hugo',
      'crane',
      'kubectl',
      'nginx-ingress-c',
      'node',
      'rootlessport',
      'webhook'
    )
    AND lp.port > 1024
    and lp.protocol = 6
  )
  -- Exclude processes running inside of Docker containers
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%'
GROUP BY
  exception_key
