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
    OR file.path LIKE '/tmp/.%/%'
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
    OR file.path LIKE '/var/tmp/.%/%'
  )
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%' -- Avoid mentioning extremely temporary files
  AND strftime('%s', 'now') - file.ctime > 20
  AND file.path NOT IN (
    '/.autorelabel',
    '/.cache/',
    '/.equarantine/',
    '/.file',
    '/.kconfig',
    '/.lesshst',
    '/.mozilla/',
    '/.netrwhist',
    '/.nofollow/',
    '/.profile',
    '/.ostree.cfs',
    '/.resolve/',
    '/.vim/',
    '/.viminfo',
    '/.vol/',
    '/.VolumeIcon.icns',
    '/dev/.blkid.tab',
    '/dev/.mdadm/',
    '/etc/.#sudoers',
    '/etc/.bootcount',
    '/etc/.clean',
    '/etc/.etckeeper',
    '/etc/.git/',
    '/etc/.gitattributes',
    '/etc/.java/',
    '/etc/.resolv.conf.systemd-resolved.bak',
    '/etc/selinux/.config_backup',
    '/etc/skel/.local/',
    '/etc/skel/.mozilla/',
    '/etc/skel/.var/',
    '/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo',
    '/tmp/._contentbarrier_installed',
    '/tmp/.accounts-agent/',
    '/tmp/.aqua/',
    '/tmp/.audio-agent/',
    '/tmp/.bazelci/',
    '/tmp/.BBE72B41371180178E084EEAF106AED4F350939DB95D3516864A1CC62E7AE82F', -- Xcode
    '/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
    '/tmp/.content-agent/',
    '/tmp/.dl.log',
    '/tmp/.docker-tmp/',
    '/tmp/.docker/',
    '/tmp/.dotnet/',
    '/tmp/.dotnet/lockfiles/',
    '/tmp/.dotnet/shm/',
    '/tmp/.dracula-tmux-data',
    '/tmp/.dracula-tmux-weather.lock',
    '/tmp/.DS_Store',
    '/tmp/.eos-update-notifier.log',
    '/tmp/.featureflags-agent/',
    '/tmp/.font-unix/',
    '/tmp/.git/',
    '/tmp/.github/',
    '/tmp/.go-version',
    '/tmp/.helmrepo',
    '/tmp/.ICE-unix/',
    '/tmp/.last_survey_prompt.yaml',
    '/tmp/.last_update_check.json',
    '/tmp/.melange.yaml',
    '/tmp/.metrics-agent/',
    '/tmp/.PKGINFO',
    '/tmp/.s.PGSQL.5432',
    '/tmp/.s.PGSQL.5432.lock',
    '/tmp/.searcher.tmp/',
    '/tmp/.ses',
    '/tmp/.settings-agent/',
    '/tmp/.terraform.lock.hcl',
    '/tmp/.terraform/',
    '/tmp/.Test-unix/',
    '/tmp/.touchpaddefaults',
    '/tmp/.ui-agent/',
    '/tmp/.updater-agent/',
    '/tmp/.venv/',
    '/tmp/.vscode.dmypy_status/',
    '/tmp/.wsdl/',
    '/tmp/.X0-lock',
    '/tmp/.X1-lock',
    '/tmp/.X11-unix/',
    '/tmp/.X2-lock',
    '/tmp/.XIM-unix/',
    '/tmp/.ydotool_socket',
    '/usr/bin/.kcapi-hasher.hmac',
    '/usr/lib/jvm/.java-1.17.0-openjdk-amd64.jinfo',
    '/usr/lib/nvidia-visual-profiler/.eclipseproduct',
    '/usr/local/bin/.swtpm',
    '/usr/local/libexec/.ksysguard/',
    '/var/.ntw_cache',
    '/var/.Parallels_swap/',
    '/var/.pwd_cache',
    '/var/.slm/',
    '/var/.slmauth/',
    '/var/.slmbackup/',
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
    '/usr/lib/x86_64-linux-gnu/.libkcapi.so.1.5.0.hmac',
    '/lib/x86_64-linux-gnu/.libkcapi.so.1.5.0.hmac',
    '/bin/X11/.kcapi-hasher.hmac',
    '/var/db/.SoftwareUpdateOptions',
    '/var/db/.StagedAppleUpgrade',
    '/var/db/.SystemPolicy-default',
    '/var/discourse/.git/',
    '/var/discourse/.github/',
    '/var/home/.duperemove.hash',
    '/var/home/.snapshots',
    '/var/home/.snapshots/',
    '/var/mail/.cache/',
    '/var/root/.bash_history',
    '/var/root/.bash_profile',
    '/var/root/.cache/',
    '/var/root/.CFUserTextEncoding',
    '/var/root/.config/',
    '/var/root/.docker/',
    '/var/root/.forward',
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
    '/var/tmp/.DS_Store',
    '/var/root/.zsh_history',
    '/var/roothome/.bash_history',
    '/var/roothome/.bash_logout',
    '/var/roothome/.bash_profile',
    '/var/roothome/.bashrc',
    '/var/roothome/.cache/',
    '/var/roothome/.cargo/',
    '/var/roothome/.config/',
    '/var/roothome/.dbus/',
    '/var/roothome/.justfile',
    '/var/roothome/.lesshst',
    '/var/roothome/.local/',
    '/var/roothome/.mozilla/',
    '/var/roothome/.osquery/',
    '/var/roothome/.ssh/',
    '/var/roothome/.var/',
    '/var/roothome/.viminfo',
    '/var/run/.heim_org.h5l.kcm-socket',
    '/var/run/.sim_diagnosticd_socket',
    '/var/run/.vfs_rsrc_streams_0x2b725bbfb94ba4ef0/',
    '/var/setup/.AppleSetupUser',
    '/var/setup/.fseventsd/',
    '/var/setup/.TemporaryItems',
    '/var/setup/.TemporaryItems/',
    '/var/tmp/.ses',
    '/var/tmp/.ses.bak'
  )
  AND file.directory NOT IN (
    '/etc/etckeeper/commit.d',
    '/etc/skel',
    '/etc/skel/.config',
    '/var/root/.provisio'
  )
  -- haven't seen any malware use sockets yet
  AND NOT file.type = 'socket'
  AND file.filename NOT LIKE '.%.swo'
  AND file.filename NOT LIKE '.%.swp'
  AND file.path NOT LIKE '%/.build-id/'
  AND file.path NOT LIKE '%/.dwz/'
  AND file.path NOT LIKE '%/.updated'
  AND file.path NOT LIKE '%/google-cloud-sdk/.install/'
  AND file.path NOT LIKE '%/lib/.lib%.hmac'
  AND file.path NOT LIKE '/%bin/bootstrapping/.default_components'
  AND file.path NOT LIKE '/lib/jvm/.java-%.jinfo'
  AND file.path NOT LIKE '/tmp/.#%'
  AND file.path NOT LIKE '/tmp/.%.gcode'
  AND file.path NOT LIKE '/tmp/.cdx.json%'
  AND file.path NOT LIKE '/tmp/.com.google.Chrome.%'
  AND file.path NOT LIKE '/tmp/.com.microsoft.Edge.%'
  AND file.path NOT LIKE '/tmp/.com.valvesoftware.Steam.%/'
  AND file.path NOT LIKE '/tmp/.dropbox-dist-%'
  AND file.path NOT LIKE '/tmp/.io.nwjs.%'
  AND file.path NOT LIKE '/tmp/.lark_cache_%'
  AND file.path NOT LIKE '/tmp/.org.chromium.Chromium%'
  AND file.path NOT LIKE '/tmp/.testcontainers-tmp-%'
  AND file.path NOT LIKE '/tmp/.tmp%/'
  AND file.path NOT LIKE '/tmp/.tmp%/stdin'
  AND file.path NOT LIKE '/tmp/.vbox-%-ipc/'
  AND file.path NOT LIKE '/tmp/.vbox-%-ipc/lock'
  AND file.path NOT LIKE '/tmp/.wine-%'
  AND file.path NOT LIKE '/tmp/.SIGN.RSA%.rsa.pub'
  AND file.path NOT LIKE '/tmp/.X1%-lock'
  AND file.path NOT LIKE '/tmp/.gradle%'
  AND file.path NOT LIKE '/tmp/.git_signing_key%'
  AND file.path NOT LIKE '/tmp/.xfsm-ICE-%'
  AND file.path NOT LIKE '/usr/lib/jvm/.java-%-openjdk-%.jinfo'
  AND file.path NOT LIKE '/usr/local/%/.keepme'
  AND file.path NOT LIKE '/var/roothome/.xauth%'
  AND file.path NOT LIKE '/var/run/.vfs_rsrc_streams_%/'
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
    file.path = '/var/tmp/.DS_Store'
    AND file.uid = 501
    AND file.mode = '0644'
    AND file.size < 10000
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
  AND NOT (
    file.path LIKE '/tmp/.comments/%.jpg.xml'
    AND file.uid > 0
    AND file.size < 15000
  )
