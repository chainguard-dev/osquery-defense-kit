SELECT name,
    path,
    cmdline,
    on_disk,
    parent,
    start_time,
    disk_bytes_written,
    cwd,
(strftime('%s', 'now') - start_time) AS age,
    disk_bytes_written / (strftime('%s', 'now') - start_time) AS bytes_per_second
FROM processes
WHERE bytes_per_second > 1000000
    AND age > 120
    AND path NOT IN (
        '/usr/libexec/coreduetd',
        '/usr/libexec/coreduetd' '/usr/bin/gnome-shell' '/usr/libexec/rosetta/oahd',
        '/usr/libexec/packagekitd',
        '/usr/libexec/secd',
        '/usr/lib/systemd/systemd-journald',
        '/usr/lib/systemd/systemd',
    )
    AND NOT (name LIKE "jbd%/dm-%" AND on_disk = -1)
    AND NOT (name = 'bindfs' AND cmdline LIKE 'bindfs -f -o fsname=%')
    AND NOT (name = 'btrfs-transaction' AND on_disk = -1)
    AND NOT (
        name = 'kernel_task'
        AND path = ''
        AND parent IN (0, 1)
        AND on_disk = -1
    )
    AND NOT (
        name = 'launchd'
        AND path = '/sbin/launchd'
        aND parent = 0
    )
    AND NOT (
        name = 'logd'
        AND cmdline = '/usr/libexec/logd'
        AND parent = 1
    )
    AND NOT name IN ('firefox', 'gopls', 'containerd', 'slack', 'chrome','goland')
    AND path NOT LIKE '/Applications/%.app/Contents/%'
    AND path NOT LIKE '/System/Applications/%'
    AND path NOT LIKE '/System/Library/%'