-- Applications setting environment variables to bypass security protections
--
-- Inpsired by BPFdoor and other intrusions
-- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/
--
-- WARNING: This query is known to require a higher than average wall time.
--
-- tags: transient state
-- interval: 300
-- platform: linux
SELECT p.pid, p.name,
  key,
  value,
  LENGTH(value) AS value_len,
  p.path,
  p.cmdline,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd
-- Querying processes first and filtering by time gives a massive 20X speed improvement
-- over querying process_envs first and JOIN'ing against processes
FROM processes p
  JOIN process_envs pe ON p.pid = pe.pid
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE -- This time should match the interval
  p.start_time > (strftime('%s', 'now') - 300)
  AND (
    key = 'HISTFILE'
    AND NOT VALUE LIKE '/home/%/.%_history'
  )
  OR (
    key = 'LD_PRELOAD'
    AND NOT p.path LIKE '%/firefox'
    AND NOT pe.value = 'libfakeroot.so'
    AND NOT pe.value LIKE ':/home/%/.local/share/Steam'
    AND NOT pe.value LIKE ':/home/%/.var/app/com.valvesoftware.Steam/%'
    AND NOT pe.value LIKE ':/snap/%'
    AND NOT pe.value LIKE '/app/bin/%'
    AND NOT pe.value LIKE 'libmozsandbox.so%'
  )
  -- setuid
  OR (
    LENGTH(value) > 1024
    AND key != 'LS_COLORS'
    AND f.mode IS NOT NULL
    AND f.mode NOT LIKE '0%'
  )