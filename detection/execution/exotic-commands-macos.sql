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
        'lushput',
        'mkfifo',
        'msfvenom',
        'nc',
        'socat'
      ) -- coin miner names
      OR REGEX_MATCH (p.name, "(pwn|xig|xmr)", 1) != "" -- malicious processes
      OR REGEX_MATCH (
        p.cmdline,
        "(bitspin|lushput|incbit|traitor|msfvenom|urllib.urlopen|nohup.*tmp|chrome.*--load-extension|tail -f /dev/null|)",
        1
      ) != "" -- suspicious things
      OR REGEX_MATCH (
        p.cmdline,
        "(UserKnownHostsFile=/dev/null|ransom|malware|plant|fsockopen|openssl.*quiet|pty.spawn|SOCK_STREAM)",
        1
      ) != "" -- Crypto miners
      OR REGEX_MATCH (
        p.cmdline,
        "(c3pool|cryptonight|f2pool|hashrate|hashvault|minerd|monero|nanopool|nicehash|stratum|wss://| --pool| --algo)",
        1
      ) != "" -- Needs to be case sensitive
      OR (
        INSTR(p.cmdline, '%Socket.%') > 0
        AND NOT p.name IN ('cc1', 'compile', 'cmake', 'cc1plus')
      )
      OR p.cmdline LIKE '%dd if=/dev/%'
  )
  AND NOT (
    p0_cmd LIKE '%UserKnownHostsFile=/dev/null%'
    AND (
      p0_cmd LIKE "%lima/%"
      OR p0_cmd LIKE "%minikube/%"
      OR p0_cmd LIKE '%@localhost'
    )
  )
  AND NOT (
    p0_cmd LIKE '%sh -i'
    AND p1_cmd LIKE '%pipenv shell'
  )
  AND NOT p0_cmd IN ('pkill -f Jabra Direct')
  AND NOT p0_cmd LIKE "%dd if=/dev/stdin conv=unblock cbs=79"
  AND NOT p1_path LIKE '/Applications/Emacs.app/Contents/MacOS/Emacs-arm64-%'
GROUP BY
  p0.pid;
