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
WHERE bytes_per_second > 2000000
    AND age > 120
    AND path NOT IN (
        '/bin/bash',
        '/usr/bin/bash',
        '/usr/bin/fish',
        '/usr/bin/gnome-shell',
        '/usr/lib/systemd/systemd-journald',
        '/usr/libexec/sharingd',
        '/usr/lib/systemd/systemd',
        '/usr/libexec/coreduetd',
        '/usr/libexec/coreduetd',
        '/usr/libexec/packagekitd',
        '/usr/libexec/rosetta/oahd',
        '/usr/libexec/secd',
        '/usr/bin/aptd',
        '/usr/sbin/screencapture'
    )
    AND NOT (name LIKE "jbd%/dm-%" AND on_disk = -1)
    AND NOT (name = 'bindfs' AND cmdline LIKE 'bindfs -f -o fsname=%')
    AND NOT (name = 'btrfs-transaction' AND on_disk = -1)
    AND NOT (name = 'kernel_task' AND path = '' AND parent IN (0, 1) AND on_disk = -1)
    AND NOT (name = 'launchd' AND path = '/sbin/launchd' AND parent = 0)
    AND NOT (name = 'logd' AND cmdline = '/usr/libexec/logd' AND parent = 1)
    AND NOT name IN ('firefox', 'gopls', 'containerd', 'slack', 'chrome','goland', 'esbuild', 'slack')
    AND path NOT LIKE '/Applications/%.app/Contents/%'
    AND path NOT LIKE '/System/Applications/%'
    AND path NOT LIKE '/System/Library/%'