-- Inpsired by BPFdoor and other intrusions
-- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/
SELECT key,
    value,
    p.pid,
    p.path,
    p.cmdline
FROM process_envs pe
    JOIN processes p ON pe.pid = p.pid
WHERE key = 'HISTFILE'
    OR (
        key = 'HOME'
        AND NOT value LIKE '/home/%'
        AND NOT value LIKE "/var/lib/%"
        AND NOT value LIKE "/Users/%"
        AND NOT value IN ('/root', '/var/spool/cups/tmp', '/var/empty', '/var/db/cmiodalassistants', '/run/systemd' '/')
    OR (
        key = 'LD_PRELOAD'
        AND NOT pe.value LIKE ':/snap/%'
        AND NOT pe.value LIKE '/app/bin/%'
        AND NOT (
            p.path LIKE '%/firefox'
            AND value LIKE 'libmozsandbox.so%'
        )
    )