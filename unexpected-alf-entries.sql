SELECT *
FROM alf_exceptions
WHERE path NOT IN (
        '/Applications/Dropbox.app/',
        '/Applications/Epson%20Software/Event%20Manager.app/Contents/Resources/Assistants/Event%20Manager/EEventManager.app/',
        '/Applications/GarageBand.app/',
        '/Applications/GoLand.app/',
        '/Applications/Google%20Chrome.app/',
        '/Applications/Logi%20Options.app/Contents/Support/LogiMgrDaemon.app/',
        '/Applications/Loom.app/',
        '/Applications/MainStage%203.app/',
        '/Applications/Parallels%20Desktop.app/',
        '/Applications/RescueTime.app/',
        '/Applications/Spotify.app/',
        '/Applications/Sketch.app/',
        '/Applications/Sonos.app/',
        '/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/',
        '/Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher.app/',
        '/Applications/Visual%20Studio%20Code.app/',
        '/Applications/Visual%20Studio%20Code.app/Contents/Frameworks/Code%20Helper.app/',
        '/Applications/Zalo.app/',
        '/usr/libexec/configd',
        '/usr/sbin/mDNSResponder',
        '/usr/sbin/racoon',
        '/usr/bin/nmblookup',
        '/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig',
        '/usr/libexec/discoveryd',
        '/usr/libexec/bootpd',
        '/usr/libexec/xartstorageremoted',
        '/System/Library/PrivateFrameworks/EmbeddedOSInstall.framework/Versions/A/XPCServices/EmbeddedOSInstallService.xpc/'
    )
    AND path NOT LIKE '/opt/homebrew/Cellar/%/bin/%'
    AND path NOT LIKE '/private/var/folders/%/go-build%/exe/%'
    AND path NOT LIKE '/System/Applications/%'
    AND path NOT LIKE '/System/Library/CoreServices/%'
    AND path NOT LIKE '/System/Library/Frameworks/%'
    AND path NOT LIKE '/%/bin/syncthing'
    AND path NOT LIKE '/Users/%/go/bin/%'
    AND path NOT LIKE '/Users/%/go/src/%'
    AND path NOT LIKE '/Users/%/Library/Application%20Support/Steam/Steam.AppBundle/Steam/'
    AND path NOT LIKE '/Users/%/.rustup/toolchains/%/bin/cargo'
    AND path NOT LIKE '/Users/%/homebrew/%/bin/%'
