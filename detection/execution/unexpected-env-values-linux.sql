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
SELECT
  pe.key,
  pe.value,
  LENGTH(pe.value) AS value_len,
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
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  -- Querying processes first and filtering by time gives a massive 20X speed improvement
  -- over querying process_envs first and JOIN'ing against processes
  processes p0
  JOIN process_envs pe ON p0.pid = pe.pid
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE -- This time should match the interval
  p0.start_time > (strftime('%s', 'now') - 300)
  AND (
    pe.key = 'HISTFILE'
    AND NOT pe.value LIKE '/home/%/.%_history'
  )
  OR (
    pe.key = 'LD_PRELOAD'
    AND NOT pe.value = ''
    AND NOT p0.path LIKE '%/firefox'
    AND NOT pe.value IN (
      'libfakeroot.so',
      '/usr/local/lib/libmimalloc.so',
      '/usr/lib/libjemalloc.so'
    )
    AND NOT pe.value LIKE ':/home/%/.local/share/Steam'
    AND NOT pe.value LIKE ':/home/%/.var/app/com.valvesoftware.Steam/%'
    AND NOT pe.value LIKE ':/home/%/.local/share/Steam/ubuntu%/gameoverlayrenderer.so:/home/%/.local/share/Steam/ubuntu%/gameoverlayrenderer.so'
    AND NOT pe.value LIKE ':/snap/%'
    AND NOT pe.value LIKE '/app/bin/%'
    AND NOT pe.value LIKE 'libmozsandbox.so%'
    AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
  )
  -- setuid
  OR (
    LENGTH(pe.value) > 1024
    AND pe.key != 'LS_COLORS'
    AND f.mode IS NOT NULL
    AND f.mode NOT LIKE '0%'
  )
