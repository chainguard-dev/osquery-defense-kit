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
  p.pid,
  p.path,
  p.cmdline,
  p.on_disk,
  p.parent,
  p.start_time,
  p.cgroup_path,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256,
  p.disk_bytes_read,
  p.cwd,
  (strftime('%s', 'now') - p.start_time) AS age,
  p.disk_bytes_read / (strftime('%s', 'now') - p.start_time) AS bytes_per_second
FROM
  processes p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash AS phash ON pp.path = phash.path
  LEFT JOIN hash ON p.path = hash.path
WHERE
  bytes_per_second > 4000000
  AND age > 180
  AND p.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p.path NOT LIKE '/System/Library/%'
  AND p.path NOT LIKE '/System/Applications/%'
  AND p.path NOT LIKE '/Library/Apple/System/Library/%'
  AND p.path NOT LIKE '/home/%/.local/share/Steam/steamapps/%'
  AND p.name NOT IN (
    'bash',
    'bwrap',
    'chrome',
    'code',
    'com.apple.NRD.UpdateBrainService',
    'docker',
    'emacs',
    'firefox',
    'osqueryi',
    'fish',
    'fleet_backend',
    'fsdaemon',
    'golangci-lint',
    'GoogleSoftwareUpdateAgent',
    'gopls',
    'grype',
    'java',
    'kube-apiserver',
    'kube-controller',
    'kube-scheduler',
    'kue',
    'launcher',
    'LogiFacecamService',
    'nautilus',
    'nessusd',
    'nix',
    'nix-daemon',
    'nvim',
    'osqueryd',
    'qemu-system-aarch64',
    'qemu-system-x86',
    'qemu-system-x86-64',
    'sh',
    'slack',
    'steam',
    'systemd',
    'thunderbird',
    'vim',
    'wineserver',
    'yay',
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
    '/usr/libexec/diskmanagementd',
    '/usr/bin/update-notifier',
    '/usr/libexec/flatpak-system-helper',
    '/usr/libexec/logd',
    '/usr/libexec/logd_helper',
    '/usr/libexec/tracker-miner-fs-3',
    '/usr/libexec/packagekitd',
    '/usr/libexec/PerfPowerServices',
    '/usr/libexec/signpost_reporter',
    '/usr/libexec/syspolicyd',
    '/usr/lib/systemd/systemd',
    '/usr/sbin/spindump',
    '/usr/sbin/systemstats'
  )
  AND NOT (
    p.name = 'bindfs'
    AND p.cmdline LIKE 'bindfs%-o fsname=%'
  )
  AND NOT (
    p.name = 'jetbrains-toolb'
    AND p.path LIKE '/tmp/.mount_jet%/jetbrains-toolbox'
  )
  AND NOT (
    p.name = 'com.apple.MobileSoftwareUpdate.UpdateBrainService'
    AND p.path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/com.apple.MobileSoftwareUpdate.UpdateBrainService.%.xpc/Contents/MacOS/com.apple.MobileSoftwareUpdate.UpdateBrainService'
  )
  AND NOT (
    p.name = 'FindMy'
    AND p.path = '/System/Applications/FindMy.app/Contents/MacOS/FindMy'
  )
  AND NOT (
    p.name = 'go'
    AND p.cmdline LIKE 'go run %'
  )
  AND NOT (
    p.name = 'kernel_task'
    AND p.path = ''
    AND p.parent IN (0, 1)
    AND p.on_disk = -1
  )
  AND NOT (
    p.name = 'node'
    AND p.cwd LIKE '%/console-ui/app'
  )
  AND NOT (
    p.name = 'ruby'
    AND p.cmdline LIKE '%brew.rb upgrade'
  )
  AND NOT (
    p.name = 'terraform-ls'
    AND p.cmdline LIKE 'terraform-ls serve%'
  )
  AND NOT (
    p.name = ""
    AND parent_name = "nvim"
  )
  AND NOT (p.path LIKE '/home/%/Apps/PhpStorm%/jbr/bin/java')
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p.pid
