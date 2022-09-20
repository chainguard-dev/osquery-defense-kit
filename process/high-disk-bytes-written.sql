SELECT p.name,
    p.path,
    p.cmdline,
    p.on_disk,
    p.parent,
    p.start_time,
    hash.sha256,
    p.disk_bytes_written,
    p.cwd,
    (strftime('%s', 'now') - start_time) AS age,
    disk_bytes_written / (strftime('%s', 'now') - start_time) AS bytes_per_second
FROM processes p
LEFT JOIN hash ON p.path = hash.path
WHERE bytes_per_second > 2000000
    AND age > 120
    AND p.path NOT IN (
        '/bin/bash',
        '/usr/bin/curl',
        '/usr/bin/bash',
        '/usr/bin/zsh',
        '/usr/bin/fish',
        '/usr/bin/gnome-shell',
        '/usr/lib/systemd/systemd-journald',
        '/usr/libexec/sharingd',
        '/usr/lib/systemd/systemd',
        '/usr/libexec/coreduetd',
        '/usr/libexec/coreduetd',
        '/usr/libexec/packagekitd',
        '/usr/lib/flatpak-system-helper',
        '/usr/libexec/rosetta/oahd',
        '/usr/libexec/secd',
        '/usr/bin/aptd',
        '/usr/bin/qemu-system-x86_64',
        '/usr/bin/bwrap',
        '/usr/sbin/screencapture',
        '/usr/lib64/thunderbird/thunderbird',
        '/usr/bin/yay'
    )
    AND NOT (name LIKE "jbd%/dm-%" AND on_disk = -1)
    AND NOT (name = 'bindfs' AND cmdline LIKE 'bindfs -f -o fsname=%')
    AND NOT (name = 'btrfs-transaction' AND on_disk = -1)
    AND NOT (name = 'kernel_task' AND p.path = '' AND parent IN (0, 1) AND on_disk = -1)
    AND NOT (name = 'launchd' AND p.path = '/sbin/launchd' AND parent = 0)
    AND NOT (name = 'logd' AND cmdline = '/usr/libexec/logd' AND parent = 1)
    AND NOT name IN (
        'firefox',
        'gopls',
        'containerd',
        'slack',
        'chrome',
        'goland',
        'esbuild',
        'slack',
        'wineserver',
        'com.apple.MobileSoftwareUpdate.UpdateBrainService'
    )
    AND p.path NOT LIKE '/Applications/%.app/Contents/%'
    AND p.path NOT LIKE '/System/Applications/%'
    AND p.path NOT LIKE '/System/Library/%'
    AND p.path NOT LIKE '/home/%/.local/share/Steam'
    AND p.path NOT LIKE '/nix/store/%/bin/%sh'