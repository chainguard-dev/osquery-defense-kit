-- Inspired by BPFdoor
-- https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
SELECT *
FROM file
WHERE (
        path LIKE "/dev/shm/%"
        OR path LIKE "/dev/%/.%"
        OR path LIKE "/dev/mqueue/%"
)
AND filename NOT IN ('.', '..')
AND filename NOT LIKE "pulse-shm-%"
AND filename NOT LIKE "u1000-Shm%"
AND filename NOT LIKE "u1000-Valve%"