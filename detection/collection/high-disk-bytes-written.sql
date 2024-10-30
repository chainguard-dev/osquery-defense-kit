-- Programs which are writing an unusually large amount of data
--
-- Can be used to detect ransomware
--
-- false positives:
--   * Package managers
--   * Backup software
--   * Build tools
--
-- references:
--   * https://attack.mitre.org/tactics/TA0009/ (Collection)
--
-- tags: transient process extra
SELECT
  -- WARNING: Writes to tmpfs are not reflected against this counter
  p0.disk_bytes_written AS bytes_written,
  (strftime('%s', 'now') - p0.start_time) AS age,
  p0.disk_bytes_written / (strftime('%s', 'now') - p0.start_time) AS bytes_written_rate,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cgroup_path AS p0_cgroup,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  -- On my Linux machine, creating a gzip archive clocks in at 6780210
  bytes_written_rate > 4000000
  AND age > 200
  AND p0.pid > 2
  AND p0.parent != 2
  AND p0.path NOT IN (
    '/Library/Application Support/Adobe/Adobe Desktop Common/HDBox/Setup',
    '/bin-busybox',
    '/bin/bash',
    '/bin/sh',
    '/opt/homebrew/bin/qemu-system-aarch64',
    '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd',
    '/usr/bin/apt',
    '/usr/bin/aptd',
    '/usr/bin/bash',
    '/usr/bin/bwrap',
    '/usr/bin/curl',
    '/usr/bin/darktable',
    '/usr/bin/dockerd',
    '/usr/bin/fish',
    '/usr/bin/git',
    '/usr/bin/gnome-disks',
    '/usr/bin/gnome-shell',
    '/usr/bin/gnome-software',
    '/usr/bin/gnome-text-editor',
    '/usr/bin/make',
    '/usr/bin/melange',
    '/usr/bin/pacman',
    '/usr/bin/qemu-system-x86_64',
    '/usr/bin/yay',
    '/usr/bin/zsh',
    '/usr/lib/baloo_file',
    '/usr/lib/baloo_file_extractor',
    '/usr/lib/flatpak-system-helper',
    '/usr/lib/snapd/snapd',
    '/usr/lib/systemd/systemd',
    '/app/libexec/mediawriter/helper',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib64/thunderbird/thunderbird',
    '/usr/libexec/coreduetd',
    '/usr/libexec/flatpak-system-helper',
    '/usr/libexec/logd_helper',
    '/usr/libexec/packagekitd',
    '/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/Current/AppleMobileDeviceHelper.app/Contents/Resources/AppleMobileBackup',
    '/usr/libexec/rosetta/oahd',
    '/usr/libexec/secd',
    '/usr/libexec/sharingd',
    '/usr/sbin/screencapture',
    '/usr/share/spotify-client/spotify'
  )
  AND NOT (
    p0.name LIKE 'jbd%/dm-%'
    AND p0.on_disk = -1
  )
  AND NOT (
    p0.name = 'bindfs'
    AND p0.cmdline LIKE 'bindfs -f -o fsname=%'
  )
  AND NOT (
    p0.name = 'btrfs-transaction'
    AND p0.on_disk = -1
  )
  AND NOT (
    p0.name = 'kernel_task'
    AND p0.path = ''
    AND p0.parent IN (0, 1)
    AND p0.on_disk = -1
  )
  AND NOT (
    p0.name = 'launchd'
    AND p0.path = '/sbin/launchd'
    AND p0.parent = 0
  )
  AND NOT (
    p0.name = 'logd'
    AND p0.cmdline = '/usr/libexec/logd'
    AND p0.parent = 1
  )
  AND NOT (
    p0.name = 'aptd'
    AND p0.cmdline = '/usr/bin/python3 /usr/sbin/aptd'
  )
  AND NOT p0.name IN (
    'GoogleUpdater',
    'Install',
    'baloo_file_extr',
    'bincapz',
    'bwrap',
    'nami',
    'topgrade',
    'vi',
    'vim',
    'cargo',
    'chrome',
    'wimlib-imagex',
    'code',
    'com.apple.MobileSoftwareUpdate.UpdateBrainService',
    'com.apple.NRD.UpdateBrainService',
    'containerd',
    'containerd-',
    'containerd-shim',
    'darkfiles',
    'dlv',
    'dnf',
    'dnf-automatic',
    'docker-index',
    'esbuild',
    'firefox',
    'osqueryd',
    'flatpak-session',
    'fsdaemon',
    'git',
    'go',
    'goland',
    'golangci-lint-v',
    'gopls',
    'qemu-system-x86',
    'grype',
    'idea',
    'java',
    'jetbrains-toolb',
    'kandji-daemon',
    'launcher',
    'limactl',
    'logioptionsplus_updater',
    'mediawriter',
    'melange',
    'melange-run',
    'monorail',
    'nessusd',
    'ninja',
    'node',
    'photorec',
    'qemu-system-aarch64',
    'qemu-system-x86_64',
    'rpm-ostree',
    'rsync',
    'rust-analyzer',
    'rustup',
    'slack',
    'snyk',
    'snyk-macos',
    'spotify',
    'staticcheck',
    'steam',
    'steam_osx',
    'syft',
    'terraform',
    'terraform-provider-apko',
    'tmux:server',
    'tracker-miner-f',
    'trivy',
    'trivy-db',
    'unattended-upgr',
    'wineserver',
    'wolfictl',
    'yum'
  )
  AND p0.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p0.path NOT LIKE '/home/%/.local/share/Steam'
  AND p0.path NOT LIKE '/Library/Application Support/%'
  AND p0.path NOT LIKE '/nix/store/%/bin/nix'
  AND p0.path NOT LIKE '/nix/store/%/bin/%sh'
  AND p0.path NOT LIKE '/nix/store/%kolide-launcher-%/bin/launcher'
  AND p0.path NOT LIKE '/System/Applications/%'
  AND p0.path NOT LIKE '/System/Library/%'
  AND p0.path NOT LIKE "%/terraform-provider-%"
  AND p0.path NOT LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND p0.path NOT LIKE '/var/folders/%/T/go-build%'
  AND p0.path NOT LIKE '/var/kolide-k2/%/osqueryd'
  AND NOT p0.cmdline LIKE '%/lib/gcloud.py components update'
  AND NOT p0.cmdline LIKE '%/gsutil %rsync%'
  AND NOT p0.cmdline LIKE '%brew.rb upgrade'
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
