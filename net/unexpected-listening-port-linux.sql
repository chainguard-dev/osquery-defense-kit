SELECT lp.address, lp.port, lp.protocol, p.uid, p.pid, p.name, p.path, p.cmdline, p.cwd, hash.sha256,
CONCAT(MIN(lp.port, 32768), ",", lp.protocol, ",", MIN(p.uid, 500), ",", p.name) AS exception_key
FROM listening_ports lp
    LEFT JOIN processes p ON lp.pid = p.pid
    LEFT JOIN hash ON p.path = hash.path
WHERE port != 0
    AND lp.address NOT IN ("224.0.0.251", "::1")
    AND lp.address NOT LIKE "127.0.0.%"
    AND lp.address NOT LIKE "172.1%"
    AND lp.address NOT LIKE "fe80::%"
    AND lp.address NOT LIKE "::ffff:127.0.0.%"
    -- All outgoing UDP (protocol 17) sessions are "listening"
    AND NOT (lp.protocol = 17 AND lp.port > 1024)
    -- Random webservers
    AND NOT (p.uid > 500 AND lp.port IN (8000,8080) AND lp.protocol=6)
    -- Filter out unmapped raw sockets
    AND NOT (p.pid == "")
    -- Exceptions: the uid is capped at 500 to represent regular users versus system users
    -- port is capped at 32768 to represent ephemeral ports
    AND NOT CONCAT(MIN(lp.port, 32768), ",", lp.protocol, ",", MIN(p.uid, 500), ",", p.name) IN (
        "10250,6,0,kubelet",
        "10256,6,0,kube-proxy",
        "17,255,500,dhcpcd",
        "1716,6,500,kdeconnectd",
        "22,6,0,sshd",
        "22000,6,500,syncthing",
        "3000,6,0,docker-proxy",
        "3000,6,472,grafana-server",
        "32768,6,0,.tailscaled-wra",
        "32768,6,0,tailscaled",
        "32768,6,0,tailscaled",
        "32768,6,500,com.docker.backend",
        "32768,6,500,spotify",
        "5000,6,500,ControlCenter",
        "5001,6,0,registry",
        "53,17,0,coredns",
        "53,6,0,coredns",
        "53,6,500,dnsmasq",
        "5355,6,193,systemd-resolve",
        "546,17,500,dhcpcd",
        "58,255,0,NetworkManager",
        "58,255,500,dhcpcd",
        "631,17,0,cups-browsed",
        "6443,6,0,kube-apiserver",
        "67,17,500,dnsmasq",
        "68,17,500,dhcpcd",
        "7000,6,500,ControlCenter",
        "80,6,60,nginx",
        "8008,6,500,controlplane",
        "8080,6,0,coredns",
        "8086,6,0,docker-proxy",
        "8086,6,0,influxd",
        "8181,6,0,coredns",
        "8443,6,0,kube-apiserver",
        "8443,6,500,controlplane",
        "9090,6,500,controlplane",
        "9153,6,0,coredns"
    )
    AND NOT (p.path LIKE ",ko-app,%" AND lp.port > 1024 and lp.protocol=6)
    AND NOT (p.name IN ("hugo") AND lp.port > 1024 and lp.protocol=6)
GROUP BY exception_key

