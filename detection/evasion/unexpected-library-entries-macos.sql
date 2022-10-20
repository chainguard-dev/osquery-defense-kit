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
    OR file.path LIKE '/Library/WebServer/Documents/%%'
    OR file.path LIKE '/Library/WebServer/CGI-Executables/%%'
  )
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND file.size > 1
  AND file.path NOT IN (
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
    '/Library/Compositions/',
    '/Library/DropboxHelperTools/',
    '/Library/Compositions/.localized',
    '/Library/Contextual Menu Items/',
    '/Library/CoreAnalytics/',
    '/Library/CoreMediaIO/',
    '/Library/Desktop Pictures/',
    '/Library/Desktop Pictures/.localizations/',
    '/Library/Desktop Pictures/.thumbnails/',
    '/Library/Developer/',
    '/Library/DirectoryServices/',
    '/Library/Documentation/',
    '/Library/DriverExtensions/',
    '/Library/DropboxHelperTools/',
    '/Library/Extensions/',
    '/Library/Filesystems/',
    '/Library/Fonts/',
    '/Library/Fonts/.uuid',
    '/Library/Frameworks/',
    '/Library/Google/',
    '/Library/GPUBundles/',
    '/Library/Graphics/',
    '/Library/Image Capture/',
    '/Library/Input Methods/',
    '/Library/InstallerSandboxes/',
    '/Library/InstallerSandboxes/.metadata_never_index',
    '/Library/InstallerSandboxes/.PKInstallSandboxManager/',
    '/Library/Internet Plug-Ins/',
    '/Library/Java/',
    '/Library/KernelCollections/',
    '/Library/KernelCollections/.file',
    '/Library/Keyboard Layouts/',
    '/Library/Keychains/',
    '/Library/LaunchAgents/',
    '/Library/LaunchDaemons/',
    '/Library/.localized',
    '/Library/Logs/',
    '/Library/Mail/',
    '/Library/Managed Preferences/',
    '/Library/Modem Scripts/',
    '/Library/Nessus/',
    '/Library/Objective-See/',
    '/Library/OpenDirectory/',
    '/Library/OSAnalytics/',
    '/Library/OSAnalytics/.DS_Store',
    '/Library/PDF Services/',
    '/Library/Perl/',
    '/Library/Plug-Ins/',
    '/Library/PreferencePanes/',
    '/Library/Preferences/',
    '/Library/Preferences/.GlobalPreferences.plist',
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
    '/Library/SystemExtensions/',
    '/Library/SystemExtensions/.staging/',
    '/Library/SystemMigration/',
    '/Library/SystemProfiler/',
    '/Library/TeX/',
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
  AND NOT file.path LIKE '/Library/Caches/.0%'
