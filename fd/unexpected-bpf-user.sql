SELECT pmm.pid,
    p.uid,
    p.path AS proc_path,
    p.cmdline AS proc_cmdline,
    pmm.path AS lib_path
FROM process_memory_map pmm
    JOIN processes p ON pmm.pid = p.pid
WHERE (lib_path LIKE "%:bpf%" OR lib_path LIKE "%libbpf%")
AND p.path != '/usr/lib/systemd/systemd'
GROUP BY pmm.pid
