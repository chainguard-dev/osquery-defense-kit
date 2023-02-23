-- Return shared memory info
--
-- tags: postmortem
-- platform: linux
SELECT shm.*,
    p.name AS p_name,
    p.path AS p_path
FROM shared_memory AS shm
    LEFT JOIN processes p ON shm.pid = p.pid;