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
  AND lp.address NOT IN ('224.0.0.251', '::1', '127.0.0.1', '127.1.1.1')
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
  AND NOT p.pid = ''
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
    '1,1,500,ping',
    '1,255,500,mtr-packet',
    '1,255,500,ping',
    '10250,6,0,k3s-server',
    '10250,6,0,kubelet',
    '10250,6,500,kubelet',
    '10250,6,500,metrics-server',
    '10254,6,101,nginx-ingress-c',
    '10256,6,0,kube-proxy',
    '10256,6,500,kube-proxy',
    '1337,6,500,kdenlive',
    '1601,6,500,rsyslogd',
    '17,255,0,.tailscaled-wra',
    '17,255,0,dhcpcd',
    '17,255,0,tailscaled',
    '17,255,500,dhcpcd',
    '17,255,500,mtr-packet',
    '1716,6,500,daemon.js',
    '1716,6,500,gjs',
    '1716,6,500,kdeconnectd',
    '17500,6,500,dropbox',
    '18000,6,500,kourier',
    '22,6,0,sshd',
    '22,6,0,systemd',
    '22,6,500,sshd',
    '22,6,500,systemd',
    '22000,6,500,syncthing',
    '2222,6,500,qemu-system-x86',
    '2379,6,500,etcd',
    '2380,6,500,etcd',
    '24800,6,500,synergy-core',
    '24802,6,500,synergy-service',
    '25,6,500,master',
    '255,255,0,atop',
    '255,255,500,mtr-packet',
    '27036,6,500,steam',
    '27500,6,500,passimd',
    '3000,6,472,grafana-server',
    '3000,6,500,grafana',
    '3000,6,500,grafana-server',
    '3000,6,500,node',
    '32768,6,0,.tailscaled-wra',
    '32768,6,0,tailscaled',
    '32768,6,500,com.docker.back',
    '32768,6,500,com.docker.backend',
    '32768,6,500,dleyna-renderer',
    '32768,6,500,goland',
    '32768,6,500,java',
    '32768,6,500,jetbrains-toolb',
    '32768,6,500,pycharm',
    '32768,6,500,rootlesskit',
    '32768,6,500,spotify',
    '32768,6,500,writerside',
    '3551,6,0,apcupsd',
    '4143,6,500,linkerd2-proxy',
    '4191,6,500,linkerd2-proxy',
    '443,6,0,docker-proxy',
    '443,6,0,tailscaled',
    '443,6,500,jcef_helper',
    '4443,6,500,metrics-server',
    '5000,6,0,registry',
    '5000,6,500,ControlCenter',
    '5000,6,500,registry',
    '5001,6,0,registry',
    '5005,6,500,rootlesskit',
    '5050,6,500,rootlesskit',
    '5355,6,193,systemd-resolve',
    '5355,6,500,systemd-resolve',
    '5432,6,70,postgres',
    '546,17,500,dhcpcd',
    '5556,6,500,dex',
    '5556,6,500,openshot-qt',
    '5558,6,500,dex',
    '58,255,0,dhcpcd',
    '58,255,0,NetworkManager',
    '58,255,100,dhcpcd',
    '58,255,100,systemd-network',
    '58,255,500,dhcpcd',
    '58,255,500,dnsmasq',
    '58,255,500,mtr-packet',
    '58,255,500,ping',
    '58,255,500,systemd-network',
    '631,17,0,cups-browsed',
    '631,17,115,cups-browsed',
    '631,17,116,cups-browsed',
    '631,17,121,cups-browsed',
    '631,17,132,cups-browsed',
    '631,17,133,cups-browsed',
    '6379,6,500,redis-server',
    '6443,6,0,k3s-server',
    '6443,6,0,kube-apiserver',
    '6443,6,500,kube-apiserver',
    '68,17,0,dhclient',
    '68,17,100,dhcpcd',
    '68,17,100,systemd-network',
    '68,17,500,dhcpcd',
    '68,17,500,systemd-network',
    '7000,6,500,ControlCenter',
    '80,6,0,apache2',
    '80,6,0,docker-proxy',
    '80,6,101,nginx',
    '80,6,33,apache2',
    '80,6,60,nginx',
    '8001,6,500,__debug_bin,',
    '8008,6,500,activator',
    '8008,6,500,autoscaler',
    '8008,6,500,controlplane',
    '8008,6,500,resolvers',
    '8008,6,500,webhook',
    '8009,6,0,java',
    '8080,6,0,coredns',
    '8080,6,0,java',
    '8081,6,500,main',
    '8086,6,0,influxd',
    '8086,6,500,controller',
    '8086,6,500,influxd',
    '8090,6,500,linkerd-policy-',
    '8123,6,500,Brackets-node',
    '8181,6,0,coredns',
    '8181,6,500,coredns',
    '8443,6,0,kube-apiserver',
    '8443,6,101,nginx-ingress-c',
    '8443,6,500,controller',
    '8443,6,500,controlplane',
    '8443,6,500,traefik',
    '8443,6,500,webhook',
    '8834,6,0,nessusd',
    '9000,6,500,authentik-proxy',
    '9000,6,500,main',
    '9000,6,500,traefik',
    '9090,6,500,controlplane',
    '9153,6,0,coredns',
    '9153,6,500,coredns',
    '9300,6,500,authentik-proxy',
    '9880,6,500,rootlesskit',
    '9999,6,500,python3'
  )
  AND NOT (
    p.path LIKE '/ko-app/%'
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    p.path LIKE '%/rootlesskit'
    AND lp.port > 1024
    and lp.protocol = 6
  )

  AND NOT (
    p.name IN (
      'caddy',
      'com.docker.back',
      'controller',
      'crane',
      'docker-proxy',
      'hugo',
      'kubectl',
      'nginx-ingress-c',
      'node',
      'qemu-system-x86',
      'rootlessport',
      'webhook'
    )
    AND lp.port > 1024
    and lp.protocol = 6
  )
  -- Exclude common/default DNS talking
  AND NOT (
    p.name IN ('aardvark-dns', 'coredns', 'dnsmasq')
    AND lp.port IN (
      53, -- DNS
      67, -- DHCP/BOOTP
      547 -- DHCPv6 server
    )
    AND lp.protocol IN (
      6, -- TCP
      17 -- UDP
    )
  )
  -- Exclude processes running inside of Docker containers
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p.cgroup_path LIKE '/kubepods.slice/%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/docker-%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%'
  AND NOT p1_cmd LIKE 'bwrap --bind%'
GROUP BY
  exception_key
