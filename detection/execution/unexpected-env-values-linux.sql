-- Applications setting environment variables to bypass security protections
--
-- Inpsired by BPFdoor and other intrusions
-- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/
--
-- WARNING: This query is known to require a higher than average wall time.
--
-- tags: transient state often
-- platform: linux
SELECT
  key,
  value,
  p.pid,
  p.path,
  p.cmdline,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd
FROM
  process_envs pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE
  (
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
