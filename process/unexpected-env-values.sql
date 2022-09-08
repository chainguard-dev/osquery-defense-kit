-- Inpsired by BPFdoor and other intrusions
-- https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/
SELECT key,
    value,
    p.pid,
    p.path,
    p.cmdline
FROM process_envs pe
    JOIN processes p ON pe.pid = p.pid
WHERE (
    key = 'HISTFILE'
    AND NOT VALUE LIKE '/Users/%/.%_history'
    AND NOT VALUE LIKE '/home/%/.%_history'
) OR (
    key = 'HOME'
    AND NOT value LIKE '/home/%'
    AND NOT value LIKE "/private/tmp/%/.brew_home"
    AND NOT value LIKE "/var/lib/%"
    AND NOT value LIKE "/Users/%"
    AND NOT value IN (
        '/',
        '/root',
        '/run/systemd',
        '/var/db/cmiodalassistants',
        '/var/empty',
        '/var/spool/cups/tmp'
    )
) OR (
    key = 'LD_PRELOAD'
    AND NOT pe.value LIKE ':/snap/%'
    AND NOT pe.value LIKE '/app/bin/%'
    AND NOT pe.value LIKE ':/home/%/.local/share/Steam'
    AND NOT p.path LIKE '%/firefox'
    AND NOT value LIKE 'libmozsandbox.so%'
)