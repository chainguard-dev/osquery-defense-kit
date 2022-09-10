SELECT pmm.pid,
    p.uid,
    p.path,
    p.cmdline
FROM process_memory_map pmm
    JOIN processes p ON pmm.pid = p.pid
WHERE pmm.path LIKE "%inode:bpf%"
OR pmm.path LIKE "%libbpf%"
GROUP BY pmm.pid;
