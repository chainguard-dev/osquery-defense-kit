-- Return the list of interface addresses
--
-- tags: postmortem
-- platform: posix
SELECT p.path AS p_path, p.name AS p_name,
    pop.*
FROM process_open_pipes AS pop
    LEFT JOIN processes p ON pop.pid = p.pid;