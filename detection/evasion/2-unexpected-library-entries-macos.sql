-- Find unexpected files in /Library
--
-- references:
--   * https://www.intezer.com/blog/incident-response/new-backdoor-sysjoker/
--
-- false positives:
--   * programs which create new Library directories
--
-- tags: persistent state filesystem seldom
-- platform: darwin
SELECT
  file.path,
  file.type,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  file.gid,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path LIKE '/Library/%'
    OR file.path LIKE '/Library/.%'
    OR file.path LIKE '/Library/%/.%'
    OR file.path LIKE '/Library/WebServer/%'
    OR file.path LIKE '/Library/WebServer/CGI-Executables/%%'
    OR file.path LIKE '/Library/WebServer/Documents/%%'
  )
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND file.size > 1
  AND file.path NOT IN (
    '/Library/.localized',
    '/Library/Apple/',
    '/Library/Application Support/',
    '/Library/Audio/',
    '/Library/AutoBugCapture/',
    '/Library/Automator/',
    '/Library/Bluetooth/',
    '/Library/Caches/',
    '/Library/Catacomb/',
    '/Library/ColorPickers/',
    '/Library/ColorSync/',
    '/Library/Components/',
    '/Library/Compositions/.localized',
    '/Library/Compositions/',
    '/Library/Contextual Menu Items/',
    '/Library/CoreAnalytics/',
    '/Library/CoreMediaIO/',
    '/Library/Desktop Pictures/.localizations/',
    '/Library/Desktop Pictures/.thumbnails/',
    '/Library/Desktop Pictures/',
    '/Library/Developer/',
    '/Library/DirectoryServices/',
    '/Library/Documentation/',
    '/Library/DriverExtensions/',
    '/Library/DropboxHelperTools/',
    '/Library/Extensions/',
    '/Library/Filesystems/',
    '/Library/Fonts/.uuid',
    '/Library/Fonts/',
    '/Library/Frameworks/',
    '/Library/Google/',
    '/Library/GPUBundles/',
    '/Library/Graphics/',
    '/Library/Image Capture/',
    '/Library/Input Methods/',
    '/Library/InstallerSandboxes/.metadata_never_index',
    '/Library/InstallerSandboxes/.PKInstallSandboxManager/',
    '/Library/InstallerSandboxes/',
    '/Library/Internet Plug-Ins/',
    '/Library/Java/',
    '/Library/KernelCollections/.file',
    '/Library/KernelCollections/',
    '/Library/Keyboard Layouts/',
    '/Library/Keychains/',
    '/Library/LaunchAgents/',
    '/Library/LaunchDaemons/',
    '/Library/Logs/',
    '/Library/Mail/',
    '/Library/Managed Preferences/',
    '/Library/Microsoft/',
    '/Library/Modem Scripts/',
    '/Library/Nessus/',
    '/Library/Objective-See/',
    '/Library/OpenDirectory/',
    '/Library/OSAnalytics/.DS_Store',
    '/Library/OSAnalytics/',
    '/Library/Parallels/',
    '/Library/PDF Services/',
    '/Library/Perl/',
    '/Library/Plug-Ins/',
    '/Library/PreferencePanes/',
    '/Library/Preferences/.GlobalPreferences.plist',
    '/Library/Preferences/',
    '/Library/Printers/',
    '/Library/PrivilegedHelperTools/',
    '/Library/Python/',
    '/Library/QuickLook/',
    '/Library/Receipts/',
    '/Library/Ruby/',
    '/Library/Sandbox/',
    '/Library/Screen Savers/',
    '/Library/ScriptingAdditions/',
    '/Library/Scripts/',
    '/Library/Security/',
    '/Library/Services/',
    '/Library/Speech/',
    '/Library/Spotlight/',
    '/Library/StagedDriverExtensions/',
    '/Library/StagedExtensions/',
    '/Library/StartupItems/',
    '/Library/SystemExtensions/.staging/',
    '/Library/SystemExtensions/',
    '/Library/SystemMigration/',
    '/Library/SystemProfiler/',
    '/Library/Tailscale/',
    '/Library/TeX/',
    '/Library/ThunderboltAccessoryFirmwareUpdates/',
    '/Library/Updates/',
    '/Library/User Pictures/',
    '/Library/User Template/',
    '/Library/Video/',
    '/Library/WebServer/',
    '/Library/WebServer/CGI-Executables/',
    '/Library/WebServer/Documents/',
    '/Library/WebServer/Documents/index.html.en',
    '/Library/WebServer/share/'
  )
  -- Probably Adobe copy protection, my guess is the host serial number or MAC addr.
  AND NOT REGEX_MATCH (
    file.path,
    '^/Library/Caches/\.([0-9ABCDEF]{12})$',
    1
  ) != ""
  AND NOT (
    file.path = '/Library/Caches/.DS_Store'
    AND magic.data = 'Apple Desktop Services Store'
    AND file.size < 9000
  )
