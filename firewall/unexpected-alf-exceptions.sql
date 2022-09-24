SELECT
  alf_exceptions.path,
  alf_exceptions.state,
  file.mtime,
  file.ctime,
  file.uid,
  file.size,
  file.type,
  hash.sha256
FROM
  alf_exceptions
  LEFT JOIN file ON alf_exceptions.path = file.path
  LEFT JOIN hash ON alf_exceptions.path = hash.path
WHERE
  alf_exceptions.path NOT IN (
    "/Applications/Dropbox.app/",
    "/Applications/Epson%20Software/Event%20Manager.app/Contents/Resources/Assistants/Event%20Manager/EEventManager.app/",
    "/Applications/GarageBand.app/",
    "/Applications/GoLand.app/",
    "/Applications/Google%20Chrome.app/",
    "/Applications/Logi%20Options.app/Contents/Support/LogiMgrDaemon.app/",
    "/Applications/Loom.app/",
    "/Applications/MainStage%203.app/",
    "/Applications/Parallels%20Desktop.app/",
    "/Applications/RescueTime.app/",
    "/Applications/Spotify.app/",
    "/Applications/Sketch.app/",
    "/Applications/Sonos.app/",
    "/Applications/ProtonMail%20Bridge.app/",
    "/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/",
    "/Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher.app/",
    "/Applications/Visual%20Studio%20Code.app/",
    "/Applications/Visual%20Studio%20Code.app/Contents/Frameworks/Code%20Helper.app/",
    "/Applications/Zalo.app/",
    "/usr/libexec/configd",
    "/usr/sbin/mDNSResponder",
    "/usr/sbin/racoon",
    "/usr/bin/nmblookup",
    "/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig",
    "/usr/libexec/discoveryd",
    "/usr/libexec/bootpd",
    "/Applications/Sketch.app/Contents/XPCServices/SketchMirrorHelper.xpc/",
    "/usr/libexec/xartstorageremoted",
    "/System/Library/PrivateFrameworks/EmbeddedOSInstall.framework/Versions/A/XPCServices/EmbeddedOSInstallService.xpc/"
  )
  AND alf_exceptions.path NOT LIKE "/%/bin/syncthing"
  AND alf_exceptions.path NOT LIKE "/opt/homebrew/Cellar/%/bin/%"
  AND alf_exceptions.path NOT LIKE "/private/var/folders/%/go-build%/exe/%"
  AND alf_exceptions.path NOT LIKE "/System/Applications/%"
  AND alf_exceptions.path NOT LIKE "/System/Library/CoreServices/%"
  AND alf_exceptions.path NOT LIKE "/System/Library/Frameworks/%"
  AND alf_exceptions.path NOT LIKE "/Users/%/bin/%"
  AND alf_exceptions.path NOT LIKE "/Users/%/go/%"
  AND alf_exceptions.path NOT LIKE "/Users/%/src/%"
  AND alf_exceptions.path NOT LIKE "/Users/%/homebrew/%/bin/%"
  AND alf_exceptions.path NOT LIKE "/Users/%/Library/Application%20Support/Steam/Steam.AppBundle/Steam/"
  AND alf_exceptions.path NOT LIKE "/Users/%/rekor-server"
  AND alf_exceptions.path NOT LIKE "%/hugo"
  AND alf_exceptions.path NOT LIKE "%/registry-redirect"
  AND alf_exceptions.path NOT LIKE "%IntelliJ%"
