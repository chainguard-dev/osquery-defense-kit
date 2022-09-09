-- Inspired by BPFdoor
-- https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
SELECT path, type, mtime
FROM file
WHERE (
        path LIKE "/dev/shm/%%"
        OR path LIKE "/dev/shm/.%"
        OR path LIKE "/dev/shm/.%/%"
        OR path LIKE "/dev/%/.%"
        OR path LIKE "/dev/.%"
        OR path LIKE "/dev/.%/%"
        OR path LIKE "/dev/mqueue/%%"
        OR path LIKE "/dev/mqueue/.%/%"
        OR path LIKE "/dev/mqueue/.%"
)
AND filename NOT IN ('..')
AND path NOT LIKE "%/./%"
AND path NOT LIKE "%/../%"
AND filename NOT LIKE "pulse-shm-%"
AND filename NOT LIKE "u1000-Shm%"
AND filename NOT LIKE "u1000-Valve%"
AND path NOT LIKE "/dev/shm/jack_db%"
AND path NOT LIKE '/dev/shm/.com.google.%'
AND path NOT LIKE '/dev/shm/.org.chromium.%'
AND path NOT LIKE '/dev/shm/wayland.mozilla.%'