-- Scan removable volumes for sketchy files
--
-- false positives:
--   * Installer packages with hidden files
--
-- references:
--   * https://attack.mitre.org/techniques/T1566/001/ (Phishing: Spearphishing Attachment)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--   * https://www.crowdstrike.com/blog/how-crowdstrike-uncovered-a-new-macos-browser-hijacking-campaign/
--
-- tags: transient volume filesystem seldom
-- platform: darwin
SELECT
  RTRIM(file.path, '/') AS trimpath,
  uid,
  filename,
  gid,
  mode,
  REGEX_MATCH (file.path, '(.*)/', 1) AS dirname,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*/(.*?)$', 1) AS basename,
  REGEX_MATCH (RTRIM(file.path, '/'), '.*\.(.*?)$', 1) AS extension,
  mtime,
  ctime,
  symlink,
  type,
  size,
  hash.sha256,
  magic.data,
  signature.identifier,
  signature.authority
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN signature ON file.path = signature.path
WHERE
  (
    file.path LIKE '/Volumes/%/%'
    OR file.path LIKE '/Volumes/%/.%'
  )
  AND file.path NOT LIKE '/Volumes/Macintosh HD%'
  AND file.path NOT LIKE '/Volumes/%/.com.apple.timemachine%'
  AND (
    extension IN (
      'command',
      'dmg',
      'gcode',
      'gz',
      'iso',
      'lnk',
      'mpkg',
      'pkg',
      'scpt',
      'sh',
      'sql'
    )
    OR file.symlink != 0
    OR basename LIKE '.%'
    OR basename LIKE '%.sql%'
    OR basename LIKE '%Chrome%'
    OR basename LIKE '%enforce%'
    OR basename LIKE '%Extension%'
    OR basename LIKE '%guard%'
    OR basename LIKE '%hidden%'
    OR basename LIKE '%Installer%'
    OR basename LIKE '%mono%'
    OR basename LIKE '%secret%'
    OR basename LIKE '%sql%'
    OR basename LIKE 'cg%'
  ) -- exceptions go here
  AND basename NOT IN (
    '._.apdisk',
    '._.TemporaryItems',
    '._.Trashes',
    '._AUTORUN.INF',
    '._Id.txt',
    '..',
    '.',
    '.actrc',
    '.angular-config.json',
    '.apdisk',
    '.background.png',
    '.background.tiff',
    '.background',
    '.bash_history',
    '.bashrc',
    '.CFUserTextEncoding',
    '.dbshell',
    '.disk_label_2x',
    '.disk_label',
    '.DS_Store',
    '.file-revisions-by-id',
    '.file',
    '.flyrc',
    '.gitconfig',
    '.iotest',
    '.keystone_install',
    '.lesshst',
    '.metadata_never_index_unless_rootfs',
    '.mysql_history',
    '.pdfbox.cache',
    '.shortcut-targets-by-id',
    '.TemporaryItems',
    '.Trashes',
    '.vol',
    '.VolumeIcon.icns',
    '.zsh_history',
    'KBFS_NOT_RUNNING',
    'LogiPresentation Installer.app',
    'pve-installer.squashfs',
    'Seagate Dashboard Installer.exe',
    'UFRII_LT_LIPS_LX_Installer.pkg'
  )
  AND authority NOT IN (
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: BlueStack Systems, Inc. (QX5T8D6EDU)',
    'Developer ID Application: Canon Inc. (XE2XNRRXZ5)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)'
  ) -- Unsigned programs here
  AND trimpath NOT IN (
    '/Volumes/Garmin Express/Install Garmin Express.pkg',
    '/Volumes/Google Chrome Canary/.keystone_install',
    '/Volumes/Google Chrome/.keystone_install',
    '/Volumes/Jabra Direct Setup/JabraDirectSetup.pkg',
    '/Volumes/macFUSE/.engine_install',
    '/Volumes/macFUSE/Install macFUSE.pkg',
    '/Volumes/PMHOME_3601DL/PMH_INST.pkg'
  )
  AND trimpath NOT LIKE '/Volumes/Blackmagic DaVinci Resolve/Install Resolve %.pkg'
  AND trimpath NOT LIKE '/Volumes/Google Earth Pro%/Install Google Earth Pro%.pkg'
  AND trimpath NOT LIKE '/Volumes/JDK %/JDK %.pkg'
  AND trimpath NOT LIKE '/Volumes/mysql-shell-%/mysql-shell-%.pkg'
  AND trimpath NOT LIKE '/Volumes/Splunk %/Install Splunk'
  AND magic.data NOT LIKE 'ASCII text%'
  AND NOT (
    magic.data = 'AppleDouble encoded Macintosh file'
    AND basename LIKE '._%'
  )
