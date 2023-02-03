-- Pick out exotic processes based on their command-line (state-based)
--
-- false positives:
--   * possible, but none known
--
-- tags: transient process state
-- platform: darwin
SELECT
  s.authority AS p0_auth,
  s.identifier AS p0_id,
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
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      p.pid
    FROM
      processes p
    WHERE
      p.name IN (
        'bitspin',
        'bpftool',
        'heyoka',
        'nstx',
        'dnscat2',
        'tuns',
        'zsh',
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
      OR p.name LIKE '%pwn%'
      OR p.name LIKE '%xig%'
      OR p.name LIKE '%xmr%'
      OR p.cmdline LIKE '%bitspin%'
      OR p.cmdline LIKE '%lushput%'
      OR p.cmdline LIKE '%incbit%'
      OR p.cmdline LIKE '%traitor%'
      OR p.cmdline LIKE '%msfvenom%' -- Unusual behaviors
      OR p.cmdline LIKE '%chattr -ia%'
      OR p.cmdline LIKE '%chflags uchg%'
      OR p.cmdline LIKE '%chmod 777 %'
      OR p.cmdline LIKE '%touch%acmr%'
      OR p.cmdline LIKE '%urllib.urlopen%'
      OR p.cmdline LIKE '%launchctl load%'
      OR p.cmdline LIKE '%launchctl bootout%'
      OR p.cmdline LIKE '%nohup%tmp%'
      OR p.cmdline LIKE '%set visible of front window to false%'
      OR p.cmdline LIKE '%chrome%--load-extension%'
      -- Crypto miners
      OR p.cmdline LIKE '%c3pool%'
      OR p.cmdline LIKE '%cryptonight%'
      OR p.cmdline LIKE '%f2pool%'
      OR p.cmdline LIKE '%hashrate%'
      OR p.cmdline LIKE '%hashvault%'
      OR p.cmdline LIKE '%minerd%'
      OR p.cmdline LIKE '%monero%'
      OR p.cmdline LIKE '%nanopool%'
      OR p.cmdline LIKE '%nicehash%'
      OR p.cmdline LIKE '%stratum%' -- Random keywords
      OR p.cmdline LIKE '%ransom%'
      OR p.cmdline LIKE '%malware%'
      OR p.cmdline LIKE '%plant%' -- Reverse shells
      OR p.cmdline LIKE '%fsockopen%'
      OR p.cmdline LIKE '%openssl%quiet%'
      OR p.cmdline LIKE '%pty.spawn%'
      OR p.cmdline LIKE '%sh -i'
      OR p.cmdline LIKE '%socat%'
      OR p.cmdline LIKE '%SOCK_STREAM%'
      OR INSTR(p.cmdline, '%Socket.%') > 0
      OR p.cmdline LIKE '%tail -f /dev/null%'
      AND NOT p.name IN ('cc1', 'compile', 'cmake', 'cc1plus')
  )
  AND NOT (
    p0.cmdline LIKE '%UserKnownHostsFile=/dev/null%'
    AND p1.name = 'limactl'
  )
  AND NOT (
    p0.cmdline LIKE '%sh -i'
    AND p1.cmdline LIKE '%pipenv shell'
  )
GROUP BY
  p0.pid;
