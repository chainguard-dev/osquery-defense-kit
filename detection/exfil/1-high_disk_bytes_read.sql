-- Programs which are reading an unusually large amount of data
--
-- Can be used to detect exfiltration
--
-- false positives:
--   * Virtual Machine managers
--   * Backup software
--   * Build tools
--
-- references:
--   * https://attack.mitre.org/tactics/TA0010/ (Exfiltration)
--
-- tags: transient process extra
SELECT
  -- WARNING: Writes to tmpfs are not reflected against this counter
  p0.disk_bytes_read AS bytes_read,
  (strftime('%s', 'now') - p0.start_time) AS age,
  p0.disk_bytes_read / (strftime('%s', 'now') - p0.start_time) AS bytes_read_rate,
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
  -- On my Linux machine, tarring up a home directory clocks in at 2,800,000 - 4,986,722
  bytes_read_rate > 3000000
  AND age > 180
  AND p0.path NOT LIKE '/app/%'
  AND p0.path NOT LIKE '/Applications/%.app/Contents/%'
  -- Don't exclude /usr so that we find things like tar & rsync
  AND p0.path NOT LIKE '/home/%/.local/share/Steam/steamapps/%'
  AND p0.path NOT LIKE '/Library/Apple/System/Library/%'
  AND p0.path NOT LIKE '/opt/%'
  AND p0.path NOT LIKE '/System/Applications/%'
  AND p0.path NOT LIKE '/System/Library/%'
  AND p0.name NOT IN (
    'apko',
    'Autodesk Fusion 360',
    'Autodesk Identity Manager',
    'baloo_file',
    'baloo_file_extr',
    'bash',
    'BDLDaemon',
    'bincapz',
    'bwrap',
    'cargo',
    'chrome',
    'clamscan',
    'code',
    'codium',
    'com.apple.MobileSoftwareUpdate.UpdateBrainService',
    'com.apple.NRD.UpdateBrainService',
    'com.apple.WebKit.Networking',
    'cpptools',
    'Disk Inventory X',
    'dnf',
    'docker',
    'elastic-endpoin',
    'elastic-endpoint',
    'electron',
    'emacs',
    'factorio',
    'Fedora Media Writer',
    'firefox',
    'firefox-bin',
    'fish',
    'fleet_backend',
    'fsdaemon',
    'fsnotifier',
    'git',
    'gnome-software',
    'go',
    'containerd-shim',
    'goland',
    'golangci-lint',
    'Google Chrome',
    'GoogleSoftwareUpdateAgent',
    'gopls',
    'grype',
    'hugo',
    'java',
    'kandji-library-manager',
    'kandji-parameter-agent',
    'kube-apiserver',
    'kube-controller',
    'kube-scheduler',
    'kue',
    'launcher',
    'LogiFacecamService',
    'mal',
    'mediawriter',
    'Meeting Center',
    'melange',
    'minecraft-launc',
    'meta',
    'Microsoft Update Assistant',
    'nautilus',
    'nessusd',
    'nix',
    'nix-daemon',
    'nvim',
    'ollama',
    'ollama-runer',
    'ollama_llama_server',
    'osqueryd',
    'osqueryi',
    'plasmashell',
    'pycharm',
    'qemu-system-aarch64',
    'qemu-system-x86',
    'qemu-system-x86-64',
    'rpi-imager',
    'rpm-ostree',
    'rsync',
    'Safari',
    'sh',
    'simdiskimaged',
    'slack',
    'snapd',
    'spotify',
    'steam',
    'steam_osx',
    'systemd',
    'terraform',
    'terraform-ls',
    'terraform-provider-apko',
    'thunderbird',
    'tilt',
    'unattended-upgr',
    'update_dyld_sim_shared_cache',
    'UpdateBrainService',
    'updatedb',
    'vim',
    'wineserver',
    'bundle',
    'rake',
    'wolfictl',
    'yay',
    'ykman-gui',
    'yum',
    'zsh',
    'ZwiftAppMetal',
    'ZwiftAppSilicon'
  )
  AND NOT p0.path IN (
    '/app/libexec/mediawriter/helper',
    '/usr/libexec/syspolicyd',
    '/usr/libexec/logd',
    '/usr/libexec/logd_helper',
    '/usr/libexec/lsd',
    '/usr/libexec/packagekitd',
    '/usr/libexec/diskimagesiod',
    '/Library/Application Support/Adobe/Adobe Desktop Common/HDBox/Setup',
    '/Library/Elastic/Endpoint/elastic-endpoint',
    '/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.BrowserDataImportingService.xpc/Contents/MacOS/com.apple.Safari.BrowserDataImportingService',
    '/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent'
  )
  AND NOT p0.path LIKE '/Library/SystemExtensions/%/io.kandji.KandjiAgent.ESF-Extension.systemextension/Contents/MacOS/io.kandji.KandjiAgent.ESF-Extension'
  AND NOT p0.path LIKE '/private/var/folders/%/T/go-build%'
  AND NOT p0.path LIKE '/Users/%/Library/Application Support/Google/GoogleUpdater/%/GoogleUpdater.app/Contents/MacOS/GoogleUpdater'
  AND NOT (
    p0.name = 'bindfs'
    AND p0.cmdline LIKE 'bindfs%-o fsname=%'
  )
  AND NOT (
    p0.name = 'jetbrains-toolb'
    AND p0.path LIKE '/tmp/.mount_jet%/jetbrains-toolbox'
  )
  AND NOT (
    p0.name LIKE 'gopls_%'
    AND p0.path LIKE '%gopls/gopls%'
  )
  AND NOT p0.path LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%com.apple.MobileSoftwareUpdate.UpdateBrainService.%.xpc/Contents/MacOS/com.apple.MobileSoftwareUpdate.UpdateBrainService'
  AND NOT (
    p0.name = 'FindMy'
    AND p0.path = '/System/Applications/FindMy.app/Contents/MacOS/FindMy'
  )
  AND NOT (
    p0.name = 'go'
    AND p0.cmdline LIKE 'go run %'
  )
  AND NOT (
    p0.name = 'kernel_task'
    AND p0.path = ''
    AND p0.parent IN (0, 1)
    AND p0.on_disk = -1
  )
  AND NOT (
    p0.name = 'node'
    AND p0.cwd LIKE '%/console-ui/app'
  )
  AND NOT (
    p0.name = 'ruby'
    AND p0.cmdline LIKE '%brew.rb upgrade'
  )
  AND NOT (
    p0.name = 'terraform-ls'
    AND p0.cmdline LIKE 'terraform-ls serve%'
  )
  AND NOT (
    p0.name = ""
    AND p1.name = "nvim"
  )
  AND NOT p0.path LIKE "%/terraform-provider-%"
  AND NOT p0_cmd LIKE '%/gcloud.py components update'
  AND NOT (
    p0.path LIKE '/home/%/Apps/PhpStorm%/jbr/bin/java'
  )
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p0.pid
