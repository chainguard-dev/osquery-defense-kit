SELECT
  p.name,
  p.path,
  p.cmdline,
  p.on_disk,
  p.parent,
  p.start_time,
  hash.sha256,
  p.disk_bytes_read,
  p.cwd,
  (strftime('%s', 'now') - start_time) AS age,
  disk_bytes_read / (strftime('%s', 'now') - start_time) AS bytes_per_second
FROM
  processes p
  LEFT JOIN hash ON p.path = hash.path
WHERE
  bytes_per_second > 2000000
  AND age > 180
  AND p.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p.path NOT LIKE '/System/Library/%'
  AND p.path NOT LIKE '/System/Applications/%'
  AND p.path NOT LIKE '/Library/Apple/System/Library/%'
  AND name NOT IN (
    'bash',
    'emacs',
    'firefox',
    'fish',
    'gopls',
    'GoogleSoftwareUpdateAgent',
    'nautilus',
    'qemu-system-x86-64',
    'qemu-system-x86',
    'slack',
    'java',
    'wineserver',
    'nix',
    'ykman-gui',
    'osqueryd',
    'zsh'
  )
  AND NOT (
    name = 'aned'
    AND cmdline = '/usr/libexec/aned'
    AND parent = 1
  )
  AND NOT (
    name = 'bindfs'
    AND cmdline LIKE 'bindfs -f -o fsname=%'
  )
  AND NOT (
    name = 'jetbrains-toolb'
    AND p.path LIKE '/tmp/.mount_jet%/jetbrains-toolbox'
  )
  AND NOT (
    name = 'chrome'
    AND p.path = '/opt/google/chrome/chrome'
  )
  AND NOT (
    name = 'com.apple.MobileSoftwareUpdate.UpdateBrainService'
    AND p.path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/com.apple.MobileSoftwareUpdate.UpdateBrainService.%.xpc/Contents/MacOS/com.apple.MobileSoftwareUpdate.UpdateBrainService'
  )
  AND NOT (
    name = 'FindMy'
    AND p.path = '/System/Applications/FindMy.app/Contents/MacOS/FindMy'
  )
  AND NOT (
    name = 'go'
    AND cmdline LIKE 'go run %'
  )
  AND NOT (
    name = 'gopls'
    AND p.path LIKE '/home/%/bin/gopls'
  )
  AND NOT (
    name = 'gopls'
    AND p.path LIKE '/home/%/gopls/gopls'
  )
  AND NOT (
    name = 'gopls'
    AND p.path LIKE '/Users/%/bin/gopls'
  )
  AND NOT (
    name = 'gopls'
    AND p.path LIKE '/Users/%/gopls/gopls'
  )
  AND NOT (
    name = 'kernel_task'
    AND p.path = ''
    AND parent IN (0, 1)
    AND on_disk = -1
  )
  AND NOT (
    name = 'launcher'
    AND p.path LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/launcher'
  )
  AND NOT (
    name = 'logd'
    AND cmdline = '/usr/libexec/logd'
    AND parent = 1
  )
  AND NOT (name = 'LogiFacecamService')
  AND NOT (
    name = 'node'
    AND cwd LIKE '%/console-ui/app'
  )
  AND NOT (
    name = 'osqueryd'
    AND p.path LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  )
  AND NOT (
    name = 'packagekitd'
    AND p.path = '/usr/libexec/packagekitd'
  )
  AND NOT (
    name = 'PerfPowerServices'
    AND p.path = '/usr/libexec/PerfPowerServices'
  )
  AND NOT (
    name = 'ruby'
    AND cmdline LIKE '%brew.rb upgrade'
  )
  AND NOT (
    name = 'signpost_reporter'
    AND cmdline = '/usr/libexec/signpost_reporter'
    AND parent = 1
  )
  AND NOT (
    name = 'snapd'
    AND p.path = '/usr/lib/snaptd/snaptd'
  )
  AND NOT (
    name = 'spindump'
    AND p.path = '/usr/sbin/spindump'
  )
  AND NOT (
    name = 'syspolicyd'
    AND p.path = '/usr/libexec/syspolicyd'
    AND parent = 1
  )
  AND NOT (
    name = 'systemd-udevd'
    AND p.path = '/usr/bin/udevadm'
  )
  AND NOT (
    name = 'systemd'
    AND p.path = '/usr/lib/systemd/systemd'
  )
  AND NOT (
    name = 'systemstats'
    AND p.path = '/usr/sbin/systemstats'
  )
  AND NOT (p.path = '/usr/bin/gnome-shell')
  AND NOT (
    name = 'terraform-ls'
    AND cmdline LIKE 'terraform-ls serve%'
  )
  AND NOT (p.path LIKE '/home/%/Apps/PhpStorm%/jbr/bin/java')
