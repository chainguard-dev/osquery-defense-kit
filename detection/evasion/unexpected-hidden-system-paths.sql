-- Find unexpected hidden directories in operating-system foldersbin/
--
-- references:
--   * https://themittenmac.com/what-does-apt-activity-look-like-on-macos/
--
-- false positives:
--   * unusual installers
--
-- platform: posix
-- tags: persistent filesystem state
SELECT
  file.path,
  file.inode,
  file.directory,
  uid,
  gid,
  mode,
  atime,
  btime,
  mtime,
  ctime,
  type,
  size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path LIKE '/lib/.%'
    OR file.path LIKE '/.%'
    OR file.path LIKE '/bin/%/.%'
    OR file.path LIKE '/dev/.%'
    OR file.path LIKE '/etc/.%'
    OR file.path LIKE '/etc/%/.%'
    OR file.path LIKE '/lib/%/.%'
    OR file.path LIKE '/libexec/.%'
    OR file.path LIKE '/Library/.%'
    OR file.path LIKE '/sbin/.%'
    OR file.path LIKE '/sbin/%/.%'
    OR file.path LIKE '/tmp/.%'
    OR file.path LIKE '/usr/bin/.%'
    OR file.path LIKE '/usr/lib/.%'
    OR file.path LIKE '/usr/lib/%/.%'
    OR file.path LIKE '/usr/libexec/.%'
    OR file.path LIKE '/usr/local/bin/.%'
    OR file.path LIKE '/usr/local/lib/.%'
    OR file.path LIKE '/usr/local/lib/.%'
    OR file.path LIKE '/usr/local/libexec/.%'
    OR file.path LIKE '/usr/local/sbin/.%'
    OR file.path LIKE '/usr/sbin/.%'
    OR file.path LIKE '/var/.%'
    OR file.path LIKE '/var/%/.%'
    OR file.path LIKE '/var/lib/.%'
    OR file.path LIKE '/var/tmp/.%'
  )
  AND file.path NOT LIKE '%/../'
  AND file.path NOT LIKE '%/./' -- Avoid mentioning extremely temporary files
  AND strftime('%s', 'now') - file.ctime > 20
  AND file.path NOT IN (
    '/.autorelabel',
    '/dev/.mdadm/',
    '/etc/.clean',
    '/etc/.java/',
    '/etc/.resolv.conf.systemd-resolved.bak',
    '/etc/selinux/.config_backup',
    '/etc/skel/.mozilla/',
    '/etc/.#sudoers',
    '/tmp/.searcher.tmp/',
    '/.file',
    '/.lesshst',
    '/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo',
    '/.mozilla/',
    '/tmp/.accounts-agent/',
    '/tmp/.audio-agent/',
    '/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
    '/tmp/.content-agent/',
    '/tmp/._contentbarrier_installed',
    '/tmp/.docker/',
    '/tmp/.docker-tmp/',
    '/tmp/.dotnet/',
    '/tmp/.dracula-tmux-data',
    '/tmp/.dracula-tmux-weather.lock',
    '/tmp/.DS_Store',
    '/tmp/.eos-update-notifier.log',
    '/tmp/.featureflags-agent/',
    '/tmp/.font-unix/',
    '/tmp/.go-version',
    '/tmp/.ICE-unix/',
    '/tmp/.last_survey_prompt.yaml',
    '/tmp/.last_update_check.json',
    '/tmp/.metrics-agent/',
    '/tmp/.PKGINFO',
    '/tmp/.settings-agent/',
    '/tmp/.terraform/',
    '/tmp/.terraform.lock.hcl',
    '/tmp/.Test-unix/',
    '/tmp/.ui-agent/',
    '/tmp/.updater-agent/',
    '/tmp/.vbox-t-ipc/',
    '/tmp/.X0-lock',
    '/tmp/.X11-unix/',
    '/tmp/.X1-lock',
    '/tmp/.X2-lock',
    '/tmp/.XIM-unix/',
    '/usr/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo',
    '/var/db/.AppleInstallType.plist',
    '/var/db/.AppleUpgrade',
    '/var/db/.com.apple.iokit.graphics',
    '/var/db/.com.intego.netupdate.serviceId',
    '/var/db/.GKRearmTimer',
    '/var/db/.LastGKApp',
    '/var/db/.LastGKReject',
    '/var/db/.MASManifest',
    '/var/db/.SoftwareUpdateOptions',
    '/var/db/.StagedAppleUpgrade',
    '/var/db/.SystemPolicy-default',
    '/var/.ntw_cache',
    '/tmp/.SIGN.RSA.chainguard-enterprise.rsa.pub',
    '/var/.Parallels_swap/',
    '/var/.pwd_cache',
    '/var/root/.bash_history',
    '/var/root/.bash_profile',
    '/var/root/.cache/',
    '/var/root/.CFUserTextEncoding',
    '/var/root/.docker/',
    '/var/root/.forward',
    '/var/root/.lesshst',
    '/var/root/.nix-channels',
    '/var/root/.nix-defexpr/',
    '/var/root/.nix-profile/',
    '/var/root/.osquery/',
    '/var/root/.Trash/',
    '/var/root/.viminfo',
    '/var/run/.heim_org.h5l.kcm-socket',
    '/var/run/.sim_diagnosticd_socket',
    '/var/run/.vfs_rsrc_streams_0x2b725bbfb94ba4ef0/',
    '/var/setup/.AppleSetupUser',
    '/var/setup/.TemporaryItems',
    '/var/setup/.TemporaryItems/',
    '/var/tmp/.ses',
    '/var/tmp/.ses.bak',
    '/.vol/',
    '/.VolumeIcon.icns'
  )
  AND file.directory NOT IN ('/etc/skel', '/etc/skel/.config')
  AND file.path NOT LIKE '/%bin/bootstrapping/.default_components'
  AND file.path NOT LIKE '/tmp/.#%'
  AND file.path NOT LIKE '/tmp/.lark_cache_%'
  AND file.path NOT LIKE '/tmp/.wine-%'
  AND file.path NOT LIKE '/tmp/.%.gcode'
  AND file.path NOT LIKE '/tmp/.vbox-%-ipc/'
  AND file.path NOT LIKE '/tmp/.io.nwjs.%'
  AND file.path NOT LIKE '/tmp/.xfsm-ICE-%'
  AND file.path NOT LIKE '/tmp/.com.google.Chrome.%'
  AND file.path NOT LIKE '/tmp/.org.chromium.Chromium%'
  AND file.path NOT LIKE '/var/run/.vfs_rsrc_streams_%/'
  AND file.path NOT LIKE '/tmp/.X1%-lock'
  AND file.path NOT LIKE '/usr/local/%/.keepme'
  AND file.path NOT LIKE '%/.build-id/'
  AND file.path NOT LIKE '%/.dwz/'
  AND file.path NOT LIKE '%/.updated'
  AND file.filename NOT LIKE '.%.swo'
  AND file.filename NOT LIKE '.%.swp'
  AND file.path NOT LIKE '%/google-cloud-sdk/.install/'
  AND NOT (
    type = 'regular'
    AND (
      filename LIKE '%.swp'
      OR size < 2
    )
  )
  AND NOT (
    type = 'regular'
    AND filename = '.placeholder'
  ) -- A curious addition seen on NixOS and Fedora machines
  AND NOT (
    file.path = '/.cache/'
    AND file.uid = 0
    AND file.gid = 0
    AND file.mode IN ('0755', '0700')
    AND file.size < 4
  ) -- Ecamm Live
  AND NOT (
    file.path LIKE "/tmp/.elive%"
    AND file.size < 7
  )
  AND NOT (
    file.path = '/.config/'
    AND file.uid = 0
    AND file.gid = 0
    AND file.mode IN ('0755', '0700')
    AND file.size = 4
  )
  AND NOT (
    file.path LIKE '/tmp/.java_pid%'
    AND file.type = 'socket'
    AND file.size = 0
  )
  AND NOT (
    file.path = '/var/root/.oracle_jre_usage/'
    AND file.size = 96
  )
