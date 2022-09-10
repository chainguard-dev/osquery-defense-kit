SELECT p.pid,
    p.name,
    p.path,
    f.directory,
    p.cmdline
FROM processes p
    JOIN file f ON p.path = f.path
WHERE directory NOT LIKE '/Applications/%.app/%'
    AND directory NOT LIKE '/home/%'
    AND directory NOT LIKE '/Library/Apple/System/Library%'
    AND directory NOT LIKE '/Library/Application Support/%/Contents/MacOS'
    AND directory NOT LIKE '/Library/Audio/Plug-Ins/%/Contents/MacOS'
    AND directory NOT LIKE '/Library/CoreMediaIO/Plug-Ins/%'
    AND directory NOT LIKE '/Library/Internet Plug-Ins/%/Contents/MacOS'
    AND directory NOT LIKE '/Library/SystemExtensions/%/at.obdev.littlesnitch.networkextension.systemextension/Contents/MacOS'
    AND directory NOT LIKE '/Library/SystemExtensions/%/com.objective-see.lulu.extension.systemextension/Contents/MacOS'
    AND directory NOT LIKE '/Library/SystemExtensions/%/com.objective-see.lulu.extension.systemextension/Contents/MacOS'
    AND directory NOT LIKE '/Library/SystemExtensions/%/com.opalcamera.OpalCamera.opalCameraExtension.systemextension/Contents/MacOS'
    AND directory NOT LIKE '/nix/store/%/bin'
    AND directory NOT LIKE '/nix/store/%/lib/%'
    AND directory NOT LIKE '/nix/store/%/libexec'
    AND directory NOT LIKE '/nix/store/%/libexec/%'
    AND directory NOT LIKE '/nix/store/%/share/%'
    AND directory NOT LIKE '/opt/%'
    AND directory NOT LIKE '/opt/homebrew/%'
    AND directory NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
    AND directory NOT LIKE '/private/var/folders/%/Contents/Frameworks/%'
    AND directory NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND directory NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND directory NOT LIKE '/private/var/folders/%/go-build%'
    AND directory NOT LIKE '/tmp/go-build%'
    AND directory NOT LIKE '/snap/%'
    AND directory NOT LIKE '/System/%'
    AND directory NOT LIKE '/Users/%'
    AND directory NOT LIKE '/Users/%/Library/Application Support/%'
    AND directory NOT LIKE '/usr/libexec/%'
    AND directory NOT LIKE '/usr/local/%/bin/%'
    AND directory NOT LIKE '/usr/local/%bin'
    AND directory NOT LIKE '/usr/local/%libexec'
    and directory NOT LIKE '/usr/local/Cellar/%'
    AND directory NOT LIKE '/usr/lib/%'
    AND directory NOT LIKE '/usr/lib64/%'
    AND directory NOT LIKE '/private/var/folders/%/bin'
    AND directory NOT LIKE '/tmp/%/bin'
    AND directory NOT IN (
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
        '/Library/Printers/DYMO/Utilities',
        '/Library/Developer/CommandLineTools/usr/bin',
        '/usr/share/code',
        '/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateAgent.app/Contents/MacOS'
    )
    AND f.path NOT IN (
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
    AND directory NOT LIKE '/Library/Application Support/Adobe/%'
    AND directory NOT LIKE '/Library/%/%.bundle/Contents/Helpers'
    AND NOT (directory='' AND name LIKE "runc%")