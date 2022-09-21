-- Events version of unexpected-executable-directory
-- Designed for execution every 5 minutes (where the parent may still be around)
SELECT p.pid,
    p.path AS fullpath,
    REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, '/', '')), '') AS basename,
    REPLACE(p.path, CONCAT('/', REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, '/', '')), '')) , '') AS dirname,
    p.cmdline,
    p.mode,
    p.cwd,
    p.euid,
    p.parent,
    p.syscall,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid,
    hash.sha256 AS parent_sha256
FROM process_events p
    LEFT JOIN processes pp ON p.parent = pp.pid
    LEFT JOIN hash ON pp.path = hash.path
WHERE p.time > (strftime('%s', 'now') -300)
-- NOTE: Everything after this is shared with process/unexpected-executable-directory
AND dirname NOT LIKE '/Applications/%.app/%'
    AND dirname NOT LIKE '/home/%'
    AND dirname NOT LIKE '/Library/Apple/System/Library%'
    AND dirname NOT LIKE '/Library/Application Support/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/Audio/Plug-Ins/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/CoreMediaIO/Plug-Ins/%'
    AND dirname NOT LIKE '/Library/Internet Plug-Ins/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/SystemExtensions/%/at.obdev.littlesnitch.networkextension.systemextension/Contents/MacOS'
    AND dirname NOT LIKE '/Library/SystemExtensions/%/com.objective-see.lulu.extension.systemextension/Contents/MacOS'
    AND dirname NOT LIKE '/Library/SystemExtensions/%/com.objective-see.lulu.extension.systemextension/Contents/MacOS'
    AND dirname NOT LIKE '/Library/SystemExtensions/%/com.opalcamera.OpalCamera.opalCameraExtension.systemextension/Contents/MacOS'
    AND dirname NOT LIKE '/Library/Developer/PrivateFrameworks/%'
    AND dirname NOT LIKE '/nix/store/%/bin'
    AND dirname NOT LIKE '/nix/store/%/lib/%'
    AND dirname NOT LIKE '/nix/store/%/libexec'
    AND dirname NOT LIKE '/nix/store/%/libexec/%'
    AND dirname NOT LIKE '/nix/store/%/share/%'
    AND dirname NOT LIKE '/opt/%'
    AND dirname NOT LIKE '/opt/homebrew/%'
    AND dirname NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
    AND dirname NOT LIKE '/private/var/folders/%/Contents/Frameworks/%'
    AND dirname NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND dirname NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND dirname NOT LIKE '/private/var/folders/%/go-build%'
    AND dirname NOT LIKE '/tmp/go-build%'
    AND dirname NOT LIKE '/snap/%'
    AND dirname NOT LIKE '/System/%'
    AND dirname NOT LIKE '/Users/%'
    AND dirname NOT LIKE '/Users/%/Library/Application Support/%'
    AND dirname NOT LIKE '/usr/libexec/%'
    AND dirname NOT LIKE '/usr/local/%/bin/%'
    AND dirname NOT LIKE '/usr/local/%bin'
    AND dirname NOT LIKE '/usr/local/%libexec'
    and dirname NOT LIKE '/usr/local/Cellar/%'
    AND dirname NOT LIKE '/usr/lib/%'
    AND dirname NOT LIKE '/usr/lib64/%'
    AND dirname NOT LIKE '/private/var/folders/%/bin'
    AND dirname NOT LIKE '/private/var/folders/%/GoLand'
    AND dirname NOT LIKE '/tmp/%/bin'
    AND dirname NOT LIKE '/usr/local/go/pkg/tool/%'
    AND dirname NOT IN (
        '/bin',
        '/Library/DropboxHelperTools/Dropbox_u501',
        '/sbin',
        '/usr/bin',
        '/usr/lib',
        '/usr/lib/bluetooth',
        '/usr/lib/cups/notifier',
        '/usr/lib/evolution-data-server',
        '/usr/lib/fwupd',
        '/usr/lib/ibus',
        '/usr/lib/libreoffice/program',
        '/usr/lib/polkit-1',
        '/usr/lib/slack',
        '/usr/lib/firefox',
        '/usr/lib/snapd',
        '/usr/lib/systemd',
        '/usr/lib/telepathy',
        '/usr/lib/udisks2',
        '/usr/lib/xorg',
        '/usr/lib64/firefox',
        '/usr/libexec',
        '/usr/libexec/ApplicationFirewall',
        '/usr/libexec/rosetta',
        '/usr/sbin',
        '/Library/PrivilegedHelperTools',
        '/Library/Printers/DYMO/Utilities',
        '/Library/Developer/CommandLineTools/usr/bin',
        '/usr/share/code',
        '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS',
        '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.8/Resources/Python.app/Contents/MacOS'
    )
    AND fullpath NOT IN (
        '/usr/libexec/AssetCache/AssetCache',
        '/Library/PrivilegedHelperTools/com.adobe.acc.installer.v2',
        '/Library/PrivilegedHelperTools/com.adobe.ARMDC.Communicator',
        '/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper',
        '/Library/PrivilegedHelperTools/com.docker.vmnetd',
        '/Library/PrivilegedHelperTools/com.macpaw.CleanMyMac4.Agent',
        '/Library/PrivilegedHelperTools/keybase.Helper',
        '/usr/lib/firefox/firefox',
        '/usr/lib64/firefox/firefox'
    )
    AND dirname NOT LIKE '/Library/%/%.bundle/Contents/Helpers'
    AND dirname NOT LIKE '/Library/%/Resources/%/Contents/MacOS'
    AND dirname NOT LIKE '/Library/Application Support/Adobe/%'
    AND dirname NOT LIKE '/Library/Developer/CommandLineTools/Library/%'
    AND NOT (dirname='' AND name LIKE "runc%")
    -- Pulumi executables are often executed from $TMPDIR
    AND NOT (dirname LIKE "/private/var/%" AND basename LIKE "pulumi-go.%")
    -- Chrome executes patches from /tmp :(
    AND NOT (dirname LIKE "/private/tmp/%" AND basename="goobspatch")