-- Find ssh sessions that are hiding from 'w'/'who'
SELECT * FROM (
    SELECT p.pid,p.name,p.cmdline,GROUP_CONCAT(DISTINCT pof.path) AS open_files
    FROM processes p
    LEFT JOIN process_open_files pof ON p.pid = pof.pid
    WHERE p.name = 'sshd'
    GROUP BY p.pid
)
WHERE INSTR(cmdline, '@notty') > 0
OR
(
    open_files != "/dev/null" AND INSTR(open_files, '/dev/ptmx') = 0
)