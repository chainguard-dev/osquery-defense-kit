SELECT *
FROM process_envs pe
    JOIN processes p ON pe.pid = p.pid
WHERE key = 'LD_PRELOAD'
AND NOT pe.value LIKE ':/snap/%'
AND NOT pe.value LIKE '/app/bin/%'
AND NOT (p.path LIKE '%/firefox' AND value LIKE 'libmozsandbox.so%')
