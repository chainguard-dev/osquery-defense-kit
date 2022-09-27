SELECT
  p.name,
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
FROM
  processes p
  LEFT JOIN hash ON p.path = hash.path
WHERE
  bytes_per_second > 2000000
  AND age > 120
  AND p.path NOT IN (
    '/bin/bash',
    '/usr/bin/aptd',
    '/usr/bin/bash',
    '/usr/bin/bwrap',
    '/usr/bin/curl',
    '/usr/bin/fish',
    '/usr/bin/gnome-shell',
    '/usr/bin/qemu-system-x86_64',
    '/usr/bin/yay',
    '/usr/bin/zsh',
    '/usr/lib/flatpak-system-helper',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd',
    '/usr/lib64/thunderbird/thunderbird',
    '/usr/libexec/coreduetd',
    '/usr/libexec/coreduetd',
    '/usr/libexec/packagekitd',
    '/usr/libexec/rosetta/oahd',
    '/usr/libexec/secd',
    '/usr/libexec/sharingd',
    '/usr/sbin/screencapture'
  )
  AND NOT (
    name LIKE "jbd%/dm-%"
    AND on_disk = -1
  )
  AND NOT (
    name = 'bindfs'
    AND cmdline LIKE 'bindfs -f -o fsname=%'
  )
  AND NOT (
    name = 'btrfs-transaction'
    AND on_disk = -1
  )
  AND NOT (
    name = 'kernel_task'
    AND p.path = ''
    AND parent IN (0, 1)
    AND on_disk = -1
  )
  AND NOT (
    name = 'launchd'
    AND p.path = '/sbin/launchd'
    AND parent = 0
  )
  AND NOT (
    name = 'logd'
    AND cmdline = '/usr/libexec/logd'
    AND parent = 1
  )
  AND NOT name IN (
    'chrome',
    'com.apple.MobileSoftwareUpdate.UpdateBrainService',
    'containerd',
    'esbuild',
    'firefox',
    'go',
    'goland',
    'gopls',
    'jetbrains-toolb',
    'slack',
    'slack',
    'wineserver'
  )
  AND p.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p.path NOT LIKE '/home/%/.local/share/Steam'
  AND p.path NOT LIKE '/nix/store/%/bin/%sh'
  AND p.path NOT LIKE '/nix/store/%/bin/nix'
  AND p.path NOT LIKE '/System/Applications/%'
  AND p.path NOT LIKE '/System/Library/%'
  AND p.path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
