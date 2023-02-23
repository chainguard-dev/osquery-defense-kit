-- Return the list of open files by process
--
-- tags: postmortem
-- platform: posix
SELECT p.path AS p_path, p.name AS p_name,
    pof.*
FROM process_open_files AS pof
    LEFT JOIN processes p ON pof.pid = p.pid;
