-- Find unexpected hidden directories in operating-system folders
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
    '/.cache/',
    '/dev/.blkid.tab',
    '/dev/.mdadm/',
    '/.equarantine/',
    '/etc/.bootcount',
    '/etc/.clean',
    '/etc/.java/',
    '/etc/.resolv.conf.systemd-resolved.bak',
    '/etc/selinux/.config_backup',
    '/etc/skel/.local/',
    '/etc/skel/.mozilla/',
    '/etc/skel/.var/',
    '/etc/.#sudoers',
    '/.file',
    '/.lesshst',
    '/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo',
    '/.mozilla/',
    '/tmp/.accounts-agent/',
    '/tmp/.audio-agent/',
    '/tmp/.bazelci/',
    '/tmp/.BBE72B41371180178E084EEAF106AED4F350939DB95D3516864A1CC62E7AE82F', -- Xcode
    '/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
    '/tmp/.content-agent/',
    '/tmp/._contentbarrier_installed',
    '/tmp/.dl.log',
    '/tmp/.docker/',
    '/tmp/.docker-tmp/',
    '/tmp/.dotnet/',
    '/tmp/.dracula-tmux-data',
    '/tmp/.dracula-tmux-weather.lock',
    '/tmp/.DS_Store',
    '/tmp/.eos-update-notifier.log',
    '/tmp/.featureflags-agent/',
    '/tmp/.font-unix/',
    '/tmp/.git/',
    '/tmp/.go-version',
    '/tmp/.helmrepo',
    '/tmp/.ICE-unix/',
    '/tmp/.last_survey_prompt.yaml',
    '/tmp/.last_update_check.json',
    '/tmp/.metrics-agent/',
    '/tmp/.PKGINFO',
    '/tmp/.searcher.tmp/',
    '/tmp/.ses',
    '/tmp/.settings-agent/',
    '/tmp/.SIGN.RSA.chainguard-enterprise.rsa.pub',
    '/tmp/.SIGN.RSA.local-melange-enterprise.rsa.pub',
    '/tmp/.SIGN.RSA..local-melange.rsa.pub',
    '/tmp/.SIGN.RSA.local-melange.rsa.pub',
    '/tmp/.SIGN.RSA.wolfi-signing.rsa.pub',
    '/tmp/.s.PGSQL.5432',
    '/tmp/.s.PGSQL.5432.lock',
    '/tmp/.terraform/',
    '/tmp/.terraform.lock.hcl',
    '/tmp/.Test-unix/',
    '/tmp/.touchpaddefaults',
    '/tmp/.ui-agent/',
    '/tmp/.updater-agent/',
    '/tmp/.vbox-t-ipc/',
    '/tmp/.vscode.dmypy_status/',
    '/tmp/.wsdl/',
    '/tmp/.X0-lock',
    '/tmp/.X11-unix/',
    '/tmp/.X1-lock',
    '/tmp/.X2-lock',
    '/tmp/.XIM-unix/',
    '/usr/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo',
    '/usr/local/bin/.swtpm',
    '/usr/local/libexec/.ksysguard/',
    '/var/db/.AppleInstallType.plist',
    '/var/db/.AppleUpgrade',
    '/var/db/.com.apple.iokit.graphics',
    '/var/db/.com.intego.netupdate.serviceId',
    '/var/db/.EntReg',
    '/var/db/.GKRearmTimer',
    '/var/db/.InstallerTMExcludes.plist',
    '/var/db/.intl8859cache.db',
    '/var/db/.LastGKApp',
    '/var/db/.LastGKReject',
    '/var/db/.lvm_setupdone',
    '/var/db/.MASManifest',
    '/var/db/.RunLanguageChooserToo',
    '/var/db/.SoftwareUpdateOptions',
    '/var/db/.StagedAppleUpgrade',
    '/var/db/.SystemPolicy-default',
    '/var/home/.duperemove.hash',
    '/var/home/.snapshots',
    '/var/mail/.cache/',
    '/var/.ntw_cache',
    '/var/.Parallels_swap/',
    '/var/.pwd_cache',
    '/var/root/.bash_history',
    '/var/root/.bash_profile',
    '/var/root/.cache/',
    '/var/root/.CFUserTextEncoding',
    '/var/root/.config/',
    '/var/root/.docker/',
    '/var/root/.forward',
    '/var/roothome/.bash_history',
    '/var/roothome/.bash_logout',
    '/var/roothome/.bash_profile',
    '/var/roothome/.bashrc',
    '/var/roothome/.cache/',
    '/var/roothome/.config/',
    '/var/roothome/.dbus/',
    '/var/roothome/.justfile',
    '/var/roothome/.local/',
    '/var/roothome/.osquery/',
    '/var/roothome/.ssh/',
    '/var/roothome/.var/',
    '/var/home/.snapshots/',
    '/var/roothome/.lesshst',
    '/var/roothome/.viminfo',
    '/var/root/.lesshst',
    '/var/root/.nix-channels',
    '/var/root/.nix-defexpr/',
    '/var/root/.nix-profile/',
    '/var/root/.nx/',
    '/var/root/.osquery/',
    '/var/root/.PenTablet/',
    '/var/root/.provisio',
    '/var/root/.ssh/',
    '/var/root/.Trash/',
    '/var/root/.viminfo',
    '/var/root/.zsh_history',
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
  AND file.directory NOT IN (
    '/etc/skel',
    '/etc/skel/.config',
    '/var/root/.provisio'
  )
  AND file.path NOT LIKE '/%bin/bootstrapping/.default_components'
  AND file.path NOT LIKE '/tmp/.#%'
  AND file.path NOT LIKE '/lib/jvm/.java-%.jinfo'
  AND file.path NOT LIKE '%/lib/.lib%.hmac'
  AND file.path NOT LIKE '/tmp/.lark_cache_%'
  AND file.path NOT LIKE '/tmp/.cdx.json%'
  AND file.path NOT LIKE '/var/roothome/.xauth%'
  AND file.path NOT LIKE '/tmp/.wine-%'
  AND file.path NOT LIKE '/tmp/.%.gcode'
  AND file.path NOT LIKE '/tmp/.vbox-%-ipc/'
  AND file.path NOT LIKE '/tmp/.io.nwjs.%'
  AND file.path NOT LIKE '/tmp/.xfsm-ICE-%'
  AND file.path NOT LIKE '/tmp/.com.google.Chrome.%'
  AND file.path NOT LIKE '/tmp/.org.chromium.Chromium%'
  AND file.path NOT LIKe '/tmp/.com.microsoft.Edge.%'
  AND file.path NOT LIKE '/var/run/.vfs_rsrc_streams_%/'
  AND file.path NOT LIKE '/tmp/.X1%-lock'
  AND file.path NOT LIKE '/usr/local/%/.keepme'
  AND file.path NOT LIKE '%/.build-id/'
  AND file.path NOT LIKE '%/.dwz/'
  AND file.path NOT LIKE '%/.updated'
  AND file.path NOT LIKE '/tmp/.dropbox-dist-%'
  AND file.filename NOT LIKE '.%.swo'
  AND file.filename NOT LIKE '.%.swp'
  AND file.path NOT LIKE '%/google-cloud-sdk/.install/'
  AND file.path NOT LIKE '/usr/lib/jvm/.java-%-openjdk-%.jinfo'
  AND NOT (
    type = 'regular'
    AND (
      filename LIKE '%.swp'
      OR filename LIKE '%.swo'
      OR filename LIKE '%.swn'
      OR size < 2
    )
  )
  AND NOT (
    type = 'regular'
    AND filename IN ('.placeholder', '.abignore', '.gitignore')
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
  AND NOT (
    file.path LIKE '/tmp/.ssh-%'
    AND file.type = "socket"
    AND file.mode = '0600'
  )
  -- still not sure what the hell this is
  AND NOT (
    file.path LIKE '/tmp/.%3D'
    AND file.size < 35000
    AND file.size > 20000
    AND file.mode = '0644'
    AND uid = 501
    AND gid = 0
  )
  -- RX100
  AND NOT (
    file.path LIKE '/var/db/.%'
    AND file.gid = 0
    AND file.uid = 0
    AND file.size = 28
    AND file.mode = '0666'
  )
