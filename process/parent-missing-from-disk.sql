-- Parent PID is not on disk
-- Reveals boopkit if a child is spawned
SELECT p.name,
    p.pid,
    p.path AS path,
    p.cmdline AS cmdline,
    p.uid,
    p.gid,
    pp.pid AS parent_pid,
    pp.name AS parent_name,
    pp.path AS parent_path,
    pp.cmdline AS parent_cmdline,
    pp.uid,
    pp.gid
FROM processes p
    JOIN processes pp ON pp.pid = p.parent
WHERE pp.on_disk != 1
AND p.pid > 2
AND pp.pid != 2 -- kthreadd
AND pp.path NOT IN ('/opt/google/chrome/chrome')