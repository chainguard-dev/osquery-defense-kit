-- Pick out exotic processes based on their command-line (state-based)
--
-- false positives:
--   * possible, but none known
--
-- tags: transient process state
-- platform: linux
SELECT
  DATETIME(f.ctime, 'unixepoch') AS p0_changed,
  DATETIME(f.mtime, 'unixepoch') AS p0_modified,
  (strftime('%s', 'now') - p0.start_time) AS p0_runtime_s,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
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
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  -- Known attack scripts
  (
    p0.name IN (
      'bitspin',
      'bpftool',
      'heyoka',
      'nstx',
      'dnscat2',
      'tuns',
      'iodine',
      'esxcli',
      'vim-cmd',
      'minerd',
      'cpuminer-multi',
      'cpuminer',
      'httpdns',
      'rshell',
      'rsh',
      'xmrig',
      'incbit',
      'insmod',
      'kmod',
      'lushput',
      'mkfifo',
      'msfvenom',
      'nc',
      'socat'
    )
    OR p0.name LIKE '%pwn%'
    OR p0.name LIKE '%xig%'
    OR p0.name LIKE '%xmr%'
    OR p0.cmdline LIKE '%--pool%'
    OR p0.cmdline LIKE '%--algo%'
    OR p0.cmdline LIKE '%--wss%'
    OR p0.cmdline LIKE '%bitspin%'
    OR p0.cmdline LIKE '%lushput%'
    OR p0.cmdline LIKE '%incbit%'
    OR p0.cmdline LIKE '%traitor%'
    OR p0.cmdline LIKE '%ethereum%'
    OR p0.cmdline LIKE '%msfvenom%'
    -- Unusual behaviors
    OR p0.cmdline LIKE '%ufw disable%'
    OR p0.cmdline LIKE '%dd if=/dev/%'
    OR p0.cmdline LIKE '%iptables -P % ACCEPT%'
    OR p0.cmdline LIKE '%iptables -F%'
    OR p0.cmdline LIKE '%chattr -ia%'
    OR p0.cmdline LIKE '%chflags uchg%'
    OR p0.cmdline LIKE '%bpftool%'
    OR p0.cmdline LIKE '%tar % .%'
    OR p0.cmdline LIKE '%tar %/.%'
    OR p0.cmdline LIKE '%.config%gcloud%'
    OR p0.cmdline LIKE '%.config/%chrome%'
    OR p0.cmdline LIKE '%touch%acmr%'
    OR p0.cmdline LIKE '%ld.so.preload%'
    OR p0.cmdline LIKE '%urllib.urlopen%'
    OR p0.cmdline LIKE '%nohup%tmp%'
    OR p0.cmdline LIKE '%chrome%--load-extension%'
    OR (
      p0.cmdline LIKE '%UserKnownHostsFile=/dev/null%'
      AND NOT p1.name = 'limactl'
    ) -- Crypto miners
    OR p0.cmdline LIKE '%hashrate%'
    OR p0.cmdline LIKE '%hashvault%'
    OR p0.cmdline LIKE '%minerd%'
    OR p0.cmdline LIKE '%nanopool%'
    OR p0.cmdline LIKE '%nicehash%'
    OR p0.cmdline LIKE '%stratum%' -- Random keywords
    OR p0.cmdline LIKE '%plant%' -- Reverse shells
    OR p0.cmdline LIKE '%/dev/%cp/%'
    OR p0.cmdline LIKE '%fsockopen%'
    OR p0.cmdline LIKE '%openssl%quiet%'
    OR p0.cmdline LIKE '%pty.spawn%'
    OR (
      p0.cmdline LIKE '%sh -i'
      AND NOT p0.path = '/usr/bin/docker'
      AND NOT p1.name IN ('sh', 'java', 'containerd-shim')
      AND NOT p1.cmdline LIKE '%pipenv shell'
      AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
      AND NOT p0.cgroup_path LIKE '/user.slice/user-1000.slice/user@1000.service/user.slice/nerdctl-%'
    )
    OR p0.cmdline LIKE '%SOCK_STREAM%'
    OR INSTR(p0.cmdline, '%Socket.%') > 0 -- Keep the shell running, as in https://blog.aquasec.com/threat-alert-kinsing-malware-container-vulnerability
    OR (
      p0.cmdline LIKE '%tail -f /dev/null%'
      AND NOT p0.cmdline LIKE 'docker run%'
      AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
      AND NOT p1.pid == 0
    )
  )
  AND NOT p0.cmdline like '%socat UNIX-LISTEN:%com.discordapp%discord-ipc%'
  AND NOT p0.cmdline IN ('nc 127.0.0.1 5900')
  AND NOT p0.name IN ('cc1', 'compile', 'cmake', 'cc1plus', 'chrome_crashpad')