-- Return the list of open sockets per process
--
-- tags: postmortem
-- platform: posix
SELECT p.path AS p_path, p.name AS p_name,
    pos.*
FROM process_open_sockets AS pos
    LEFT JOIN processes p ON pos.pid = p.pid;