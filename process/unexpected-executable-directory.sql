SELECT p.pid,
    p.name,
    p.path,
    p.euid,
    p.gid,
    f.directory,
    p.cmdline,
    hash.sha256
FROM processes p
    JOIN file f ON p.path = f.path
    JOIN hash ON hash.path = p.path
WHERE f.directory NOT LIKE '/Applications/%.app/%'
    AND f.directory NOT LIKE '/home/%'
    AND f.directory NOT LIKE '/Library/Apple/System/Library%'
    AND f.directory NOT LIKE '/Library/Application Support/%/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/Audio/Plug-Ins/%/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/CoreMediaIO/Plug-Ins/%'
    AND f.directory NOT LIKE '/Library/Internet Plug-Ins/%/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/SystemExtensions/%/at.obdev.littlesnitch.networkextension.systemextension/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/SystemExtensions/%/com.objective-see.lulu.extension.systemextension/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/SystemExtensions/%/com.objective-see.lulu.extension.systemextension/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/SystemExtensions/%/com.opalcamera.OpalCamera.opalCameraExtension.systemextension/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/Developer/PrivateFrameworks/%'
    AND f.directory NOT LIKE '/nix/store/%/bin'
    AND f.directory NOT LIKE '/nix/store/%/lib/%'
    AND f.directory NOT LIKE '/nix/store/%/libexec'
    AND f.directory NOT LIKE '/nix/store/%/libexec/%'
    AND f.directory NOT LIKE '/nix/store/%/share/%'
    AND f.directory NOT LIKE '/opt/%'
    AND f.directory NOT LIKE '/opt/homebrew/%'
    AND f.directory NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%.xpc/Contents/MacOS'
    AND f.directory NOT LIKE '/private/var/folders/%/Contents/Frameworks/%'
    AND f.directory NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND f.directory NOT LIKE '/private/var/folders/%/Contents/MacOS'
    AND f.directory NOT LIKE '/private/var/folders/%/go-build%'
    AND f.directory NOT LIKE '/tmp/go-build%'
    AND f.directory NOT LIKE '/snap/%'
    AND f.directory NOT LIKE '/System/%'
    AND f.directory NOT LIKE '/Users/%'
    AND f.directory NOT LIKE '/Users/%/Library/Application Support/%'
    AND f.directory NOT LIKE '/usr/libexec/%'
    AND f.directory NOT LIKE '/usr/local/%/bin/%'
    AND f.directory NOT LIKE '/usr/local/%bin'
    AND f.directory NOT LIKE '/usr/local/%libexec'
    and f.directory NOT LIKE '/usr/local/Cellar/%'
    AND f.directory NOT LIKE '/usr/lib/%'
    AND f.directory NOT LIKE '/usr/lib64/%'
    AND f.directory NOT LIKE '/private/var/folders/%/bin'
    AND f.directory NOT LIKE '/tmp/%/bin'
    AND f.directory NOT LIKE '/usr/local/go/pkg/tool/%'
    AND f.directory NOT IN (
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
    AND f.directory NOT LIKE '/Library/%/%.bundle/Contents/Helpers'
    AND f.directory NOT LIKE '/Library/%/Resources/%/Contents/MacOS'
    AND f.directory NOT LIKE '/Library/Application Support/Adobe/%'
    AND f.directory NOT LIKE '/Library/Developer/CommandLineTools/Library/%'
    AND NOT (f.directory='' AND name LIKE "runc%")