-- Inpsired by BPFdoor and other intrusions
-- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/
SELECT
  key,
  value,
  p.pid,
  p.path,
  p.cmdline,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  hash.sha256
FROM
  process_envs pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  (
    key = 'HISTFILE'
    AND NOT VALUE LIKE '/Users/%/.%_history'
    AND NOT VALUE LIKE '/home/%/.%_history'
  )
  OR (
    key = 'LD_PRELOAD'
    AND NOT p.path LIKE '%/firefox'
    AND NOT pe.value = "libfakeroot.so"
    AND NOT pe.value LIKE ':/home/%/.local/share/Steam'
    AND NOT pe.value LIKE ':/home/%/.var/app/com.valvesoftware.Steam/%'
    AND NOT pe.value LIKE ':/snap/%'
    AND NOT pe.value LIKE '/app/bin/%'
    AND NOT pe.value LIKE 'libmozsandbox.so%'
  )
  OR (
    key = 'DYLD_INSERT_LIBRARIES' -- sort of obsolete, but may affect SIP abusers
  )
  OR (
    key = 'DYLD_FRAMEWORK_PATH' -- sort of obsolete, but may affect SIP abusers
  )
