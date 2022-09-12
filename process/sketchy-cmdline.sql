SELECT p.pid,
    p.path,
    p.name,
    p.cmdline,
    p.cwd,
    p.euid,
    p.parent,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid
FROM processes p
    JOIN processes pp ON p.parent = pp.pid
WHERE

-- Known attack scripts
p.cmdline LIKE "%bitspin%" OR
p.cmdline LIKE "%lushput%" OR
p.cmdline LIKE "%incbit%" OR
p.cmdline LIKE "%traitor%" OR
p.cmdline LIKE "%msfvenom%" OR
p.cmdline LIKE "%pwn%" OR
p.cmdline LIKE "%attack%" OR
-- Unusual behaviors
p.cmdline LIKE "%ufw disable%" OR
p.cmdline LIKE "%iptables -P % ACCEPT%" OR
p.cmdline LIKE "%iptables -F%" OR
p.cmdline LIKE "%chattr -ia%" OR
p.cmdline LIKE "%bpftool%" OR
p.cmdline LIKE "%base64%" OR
p.cmdline LIKE "%xxd%" OR
p.cmdline LIKE "%touch%acmr%" OR
p.cmdline LIKE "%ld.so.preload%" OR
p.cmdline LIKE "%urllib.urlopen%" OR
p.cmdline LIKE "%nohup%tmp%" OR
-- Crypto miners
p.cmdline LIKE "%c3pool%" OR
p.cmdline LIKE "%cryptonight%" OR
p.cmdline LIKE "%f2pool%" OR
p.cmdline LIKE "%hashrate%" OR
p.cmdline LIKE "%hashvault%" OR
p.cmdline LIKE "%minerd%" OR
p.cmdline LIKE "%monero%" OR
p.cmdline LIKE "%nanopool%" OR
p.cmdline LIKE "%nicehash%" OR
p.cmdline LIKE "%stratum%" OR
p.cmdline LIKE "%xig%" OR
p.cmdline LIKE "%xmr%" OR
-- Random keywords
p.cmdline LIKE "%ransom%" OR
p.cmdline LIKE "%malware%" OR
p.cmdline LIKE "%plant%" OR
-- Reverse shells
p.cmdline LIKE '%/dev/tcp/%' OR
p.cmdline LIKE '%/dev/udp/%' OR
p.cmdline LIKE '%fsockopen%' OR
p.cmdline LIKE '%openssl%quiet%' OR
p.cmdline LIKE '%pty.spawn%' OR
p.cmdline LIKE '%sh -i' OR
p.cmdline LIKE '%socat%' OR
p.cmdline LIKE '%SOCK_STREAM%' OR
p.cmdline LIKE '%Socket.fork%' OR
p.cmdline LIKE '%Socket.new%' OR
p.cmdline LIKE '%socket.socket%' OR
p.name IN ('nc', 'mkfifo')

