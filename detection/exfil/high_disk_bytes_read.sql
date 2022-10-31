-- Programs which are reading an unusually large amount of data
--
-- Can be used to detect exfiltration
--
-- false positives:
--   * Virtual Machine managers
--   * Backup software
--
-- references:
--   * https://attack.mitre.org/tactics/TA0010/ (Exfiltration)
--
-- tags: transient process
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
  bytes_per_second > 3000000
  AND age > 180
  AND p.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p.path NOT LIKE '/System/Library/%'
  AND p.path NOT LIKE '/System/Applications/%'
  AND p.path NOT LIKE '/Library/Apple/System/Library/%'
  AND p.path NOT LIKE '/home/%/.local/share/Steam/steamapps/%'
  AND name NOT IN (
    'bash',
    'bwrap',
    'chrome',
    'emacs',
    'firefox',
    'fish',
    'fleet_backend',
    'fsdaemon',
    'GoogleSoftwareUpdateAgent',
    'gopls',
    'grype',
    'java',
    'launcher',
    'LogiFacecamService',
    'nautilus',
    'nessusd',
    'nix',
    'osqueryd',
    'qemu-system-aarch64',
    'qemu-system-x86',
    'qemu-system-x86-64',
    'slack',
    'steam',
    'thunderbird',
    'systemd',
    'wineserver',
    'ykman-gui',
    'zsh'
  )
  AND NOT p.path IN (
    '/usr/bin/apt',
    '/usr/bin/darktable',
    '/usr/bin/dockerd',
    '/usr/bin/gnome-shell',
    '/usr/bin/udevadm',
    '/usr/libexec/aned',
    '/usr/libexec/coreduetd',
    '/usr/libexec/flatpak-system-helper',
    '/usr/libexec/logd',
    '/usr/libexec/logd_helper',
    '/usr/libexec/packagekitd',
    '/usr/libexec/PerfPowerServices',
    '/usr/libexec/signpost_reporter',
    '/usr/libexec/syspolicyd',
    '/usr/lib/systemd/systemd',
    '/usr/sbin/spindump',
    '/usr/sbin/systemstats'
  )
  AND NOT (
    name = 'bindfs'
    AND cmdline LIKE 'bindfs%-o fsname=%'
  )
  AND NOT (
    name = 'jetbrains-toolb'
    AND p.path LIKE '/tmp/.mount_jet%/jetbrains-toolbox'
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
    name = 'kernel_task'
    AND p.path = ''
    AND parent IN (0, 1)
    AND on_disk = -1
  )
  AND NOT (
    name = 'node'
    AND cwd LIKE '%/console-ui/app'
  )
  AND NOT (
    name = 'ruby'
    AND cmdline LIKE '%brew.rb upgrade'
  )
  AND NOT (
    name = 'terraform-ls'
    AND cmdline LIKE 'terraform-ls serve%'
  )
  AND NOT (p.path LIKE '/home/%/Apps/PhpStorm%/jbr/bin/java')
