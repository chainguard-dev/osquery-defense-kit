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
    '._.apdisk',
    '.apdisk',
    '._AUTORUN.INF',
    '.background',
    '.background.png',
    '.disk_label',
    '.keystone_install',
    '.CFUserTextEncoding',
    '.actrc',
    '.angular-config.json',
    '.mysql_history',
    '.lesshst',
    '.gitconfig',
    '.flyrc',
    '.dbshell',
    '.bash_history',
    '.bashrc',
    '.disk_label_2x',
    '.DS_Store',
    '.file',
    'LogiPresentation Installer.app',
    '.file-revisions-by-id',
    '._Id.txt',
    '.iotest',
    '.metadata_never_index_unless_rootfs',
    'Seagate Dashboard Installer.exe',
    '.shortcut-targets-by-id',
    '._.TemporaryItems',
    '.TemporaryItems',
    '._.Trashes',
    '.zsh_history',
    '.Trashes',
    '.vol',
    '.VolumeIcon.icns'
  )
  AND authority NOT IN (
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Canon Inc. (XE2XNRRXZ5)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)'
  ) -- Unsigned programs here
  AND trimpath NOT IN (
    '/Volumes/Google Chrome/.keystone_install',
    '/Volumes/Google Chrome Canary/.keystone_install',
    '/Volumes/Garmin Express/Install Garmin Express.pkg',
    '/Volumes/PMHOME_3601DL/PMH_INST.pkg',
    '/Volumes/Jabra Direct Setup/JabraDirectSetup.pkg'
  )
  AND trimpath NOT LIKE '/Volumes/JDK %/JDK %.pkg'
  AND trimpath NOT LIKE '/Volumes/mysql-shell-%/mysql-shell-%.pkg'
