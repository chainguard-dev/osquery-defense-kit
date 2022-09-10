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
p.cmdline LIKE "%treason%" OR
-- Unusual behaviors
p.cmdline LIKE "%ufw disable%" OR
p.cmdline LIKE "%iptables -P INPUT ACCEPT%" OR
p.cmdline LIKE "%iptables -P OUTPUT ACCEPT%" OR
p.cmdline LIKE "%iptables -P FORWARD ACCEPT%" OR
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
