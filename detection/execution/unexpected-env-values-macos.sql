-- Applications setting environment variables to bypass security protections
--
-- Inpsired by BPFdoor and other intrusions
-- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/
--
-- WARNING: This query is known to require a higher than average wall time.
--
-- interval: 20
-- platform: darwin
SELECT
  key,
  value,
  p.pid,
  p.path,
  p.cmdline,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd
-- Querying processes first and filtering by time gives a massive 20X speed improvement
-- over querying process_envs first and JOIN'ing against processes
FROM processes p
  LEFT JOIN process_envs pe ON p.pid = pe.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
WHERE -- This time should match the interval
  p.start_time > (strftime('%s', 'now') - 20)
  AND (
    key = 'HISTFILE'
    AND NOT VALUE LIKE '/Users/%/.%_history'
  )
  OR (
    key = 'LD_PRELOAD'
    AND NOT p.path LIKE '%/firefox'
    AND NOT pe.value = 'libfakeroot.so'
    AND NOT pe.value LIKE 'libmozsandbox.so%'
    AND NOT pe.value LIKE ':/snap/%' -- Yes, on macOS (emote)
  )
  OR (
    key = 'DYLD_INSERT_LIBRARIES' -- actively exploited on programs which disable library security
  )
  OR (
    key = 'DYLD_FRAMEWORK_PATH' -- sort of obsolete, but may affect SIP abusers
  )
