-- Find programs where fd0 (stdin), fd1 (stdout), or fd2 (stderr) are connected to a socket
--
-- false positives:
--   * none known
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: process state
-- platform: posix
SELECT p.uid,
    p.euid,
    pos.protocol,
    pos.pid,
    pos.remote_address,
    pos.local_address,
    pos.local_port,
    pos.remote_port,
    p.name,
    p.start_time,
    p.parent,
    p.cgroup_path,
    p.path,
    pos.state
FROM processes p
    JOIN process_open_sockets pos ON p.pid = pos.pid
    WHERE fd < 3 AND family != 1;
