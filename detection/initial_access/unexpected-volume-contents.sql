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
      'lnk',
      'gcode',
      'mpkg',
      'pkg',
      'scpt',
      'dmg',
      'iso',
      'gz',
      'sh',
      'sql'
    )
    OR file.symlink != 0
    OR basename LIKE '.%'
    OR basename LIKE '%.sql%'
    OR basename LIKE '%Chrome%'
    OR basename LIKE '%Extension%'
    OR basename LIKE '%enforce%'
    OR basename LIKE '%hidden%'
    OR basename LIKE '%Installer%'
    OR basename LIKE '%mono%'
    OR basename LIKE '%secret%'
    OR basename LIKE '%sql%'
    OR basename LIKE '%guard%'
    OR basename LIKE 'cg%'
  ) -- exceptions go here
  AND basename NOT IN (
    '.',
    '..',
    '.actrc',
    '.angular-config.json',
    '._.apdisk',
    '.apdisk',
    '._AUTORUN.INF',
    '.background',
    '.background.png',
    '.background.tiff',
    '.bash_history',
    '.bashrc',
    '.CFUserTextEncoding',
    '.dbshell',
    '.disk_label',
    '.disk_label_2x',
    '.DS_Store',
    '.file',
    '.file-revisions-by-id',
    '.flyrc',
    '.gitconfig',
    '._Id.txt',
    '.iotest',
    '.keystone_install',
    '.lesshst',
    'LogiPresentation Installer.app',
    '.metadata_never_index_unless_rootfs',
    '.mysql_history',
    '.pdfbox.cache',
    'pve-installer.squashfs',
    'Seagate Dashboard Installer.exe',
    '.shortcut-targets-by-id',
    '._.TemporaryItems',
    '.TemporaryItems',
    '._.Trashes',
    '.Trashes',
    'UFRII_LT_LIPS_LX_Installer.pkg',
    '.vol',
    '.VolumeIcon.icns',
    '.zsh_history'
  )
  AND authority NOT IN (
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Canon Inc. (XE2XNRRXZ5)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)'
  ) -- Unsigned programs here
  AND trimpath NOT IN (
    '/Volumes/Google Chrome/.keystone_install',
    '/Volumes/Google Chrome Canary/.keystone_install',
    '/Volumes/macFUSE/Install macFUSE.pkg',
    '/Volumes/macFUSE/.engine_install',
    '/Volumes/Garmin Express/Install Garmin Express.pkg',
    '/Volumes/PMHOME_3601DL/PMH_INST.pkg',
    '/Volumes/Jabra Direct Setup/JabraDirectSetup.pkg'
  )
  AND trimpath NOT LIKE '/Volumes/JDK %/JDK %.pkg'
  AND trimpath NOT LIKE '/Volumes/Google Earth Pro%/Install Google Earth Pro%.pkg'
  AND trimpath NOT LIKE '/Volumes/mysql-shell-%/mysql-shell-%.pkg'
  AND trimpath NOT LIKE '/Volumes/Blackmagic DaVinci Resolve/Install Resolve %.pkg'
  AND magic.data NOT LIKE 'ASCII text%'
  AND NOT (
    magic.data = 'AppleDouble encoded Macintosh file'
    AND basename LIKE '._%'
  )
