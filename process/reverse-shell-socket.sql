-- An alternate way to discover reverse shells, inspired by the osxattack pack
SELECT DISTINCT(processes.pid),
    processes.parent,
    processes.name,
    processes.path,
    processes.cmdline,
    processes.cwd,
    processes.root,
    processes.uid,
    processes.gid,
    processes.start_time,
    process_open_sockets.remote_address,
    process_open_sockets.remote_port,
    (
        SELECT cmdline
        FROM processes AS parent_cmdline
        WHERE pid = processes.parent
    ) AS parent_cmdline
FROM processes
    JOIN process_open_sockets USING (pid)
    LEFT OUTER JOIN process_open_files ON processes.pid = process_open_files.pid
WHERE name IN ('sh', 'bash', 'perl', 'python')
    AND process_open_files.pid IS NULL
    AND process_open_sockets.remote_port > 0;