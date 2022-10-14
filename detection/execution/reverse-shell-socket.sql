-- Uncover reverse-shell processes
--
-- refs:
--   * https://www.invicti.com/blog/web-security/understanding-reverse-shells/
--   * https://attack.mitre.org/techniques/T1059/ (Command & Scripting Interpreter)
--
-- false-positives:
--   * none known
--
-- tags: transient process state often
-- platform: posix
SELECT DISTINCT
  (p.pid),
  p.parent,
  p.name,
  p.path,
  p.cmdline,
  p.cwd,
  p.root,
  p.uid,
  p.gid,
  p.start_time,
  pos.remote_address,
  pos.remote_port,
  pp.cmdline,
  pp.path
FROM
  process_open_files pof
  JOIN process_open_sockets pos USING (pid)
  LEFT JOIN processes p ON pof.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT OUTER JOIN process_open_files ON p.pid = process_open_files.pid
WHERE
  p.name IN ('sh', 'bash', 'perl', 'python')
  AND pof.pid IS NULL
  AND pos.remote_port > 0
  AND NOT (
    p.path = '/usr/bin/bash'
    AND pp.cmdline LIKE 'pacman -S%'
  )
