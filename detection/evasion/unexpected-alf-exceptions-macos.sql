-- macOS application layer firewall (ALF) service exceptions.
--
-- false positives:
--   * locally built software
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  ae.path,
  ae.state,
  file.mtime,
  file.ctime,
  file.uid,
  file.directory,
  file.size,
  file.type,
  hash.sha256,
  signature.identifier,
  signature.authority,
  CONCAT (
    signature.authority,
    ',',
    signature.identifier,
    ',',
    ae.path,
    ',',
    MIN(file.uid, 501)
  ) AS exception_key
FROM
  alf_exceptions ae
  LEFT JOIN file ON ae.path = file.path
  LEFT JOIN hash ON ae.path = hash.path
  LEFT JOIN signature ON ae.path = signature.path
WHERE -- NOTE:We intentionally want to preserve missing files
  -- Unfortunately, there is no column for when an exception was granted, so
  -- we're currently unable to filter out old entries.
  exception_key NOT IN (
    ',,/Applications/Google%20Chrome.app/,',
    ',,/Applications/IntelliJ%20IDEA.app/,',
    ',,/Applications/ProtonMail%20Bridge.app/,',
    ',,/Applications/Visual%20Studio%20Code.app/,',
    ',,/Applications/Visual%20Studio%20Code.app/Contents/Frameworks/Code%20Helper.app/,',
    ',,/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig,',
    ',,/usr/bin/nmblookup,',
    ',,/usr/libexec/discoveryd,',
    ',iodined-55554944d1ffcb236a84363d9b667be6a1742a17,/usr/local/sbin/iodined,501', -- thanks Jed!
    ',java,/opt/homebrew/Cellar/openjdk/19/libexec/openjdk.jdk/Contents/Home/bin/java,501',
    'Apple Mac OS Application Signing,com.apple.garageband10,/Applications/GarageBand.app/,0',
    'Apple Mac OS Application Signing,com.utmapp.QEMULauncher,/Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher.app/,0',
    'Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension,/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/,0',
    'Developer ID Application: Bohemian Coding (WUGMZZ5K46),com.bohemiancoding.sketch3,/Applications/Sketch.app/,501',
    'Developer ID Application: Bohemian Coding (WUGMZZ5K46),com.bohemiancoding.SketchMirrorHelper,/Applications/Sketch.app/Contents/XPCServices/SketchMirrorHelper.xpc/,501',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW),com.brother.utility.WorkflowAppControlServer,/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/,0',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK),com.getdropbox.dropbox,/Applications/Dropbox.app/,501',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.goland,/Applications/GoLand.app/,501',
    'Developer ID Application: Opentest, Inc. (QGD2ZPXZZG),com.loom.desktop,/Applications/Loom.app/,501',
    'Developer ID Application: RescueTime, Inc (FSY4RB8H39),com.rescuetime.RescueTime,/Applications/RescueTime.app/,0',
    'Developer ID Application: Sonos, Inc. (2G4LW83Q3E),com.sonos.macController,/Applications/Sonos.app/,501',
    'Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client,/Applications/Spotify.app/,501',
    'Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM),com.vng.zalo,/Applications/Zalo.app/,501',
    'Software Signing,com.apple.bootpd,/usr/libexec/bootpd,0',
    'Software Signing,com.apple.configd,/usr/libexec/configd,0',
    'Software Signing,com.apple.controlcenter,/System/Library/CoreServices/ControlCenter.app/,0',
    'Software Signing,com.apple.EmbeddedOSInstallService,/System/Library/PrivateFrameworks/EmbeddedOSInstall.framework/Versions/A/XPCServices/EmbeddedOSInstallService.xpc/,0',
    'Software Signing,com.apple.mDNSResponder,/usr/sbin/mDNSResponder,0',
    'Software Signing,com.apple.Music,/System/Applications/Music.app/,0',
    'Software Signing,com.apple.nc,/usr/bin/nc,0',
    'Software Signing,com.apple.racoon,/usr/sbin/racoon,0',
    'Software Signing,com.apple.universalcontrol,/System/Library/CoreServices/UniversalControl.app/,0',
    'Software Signing,com.apple.WebKit.Networking,/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/,0',
    'Software Signing,com.apple.xartstorageremoted,/usr/libexec/xartstorageremoted,0'
  )
  AND NOT (
    signature.identifier LIKE 'cargo-%'
    AND ae.path LIKE '/Users/%/.rustup/%'
  )
  AND NOT (
    signature.identifier LIKE 'fake-%'
    AND ae.path LIKE '%/exe/fake'
  )
  AND NOT (
    signature.identifier LIKE 'mariadbd-%'
    AND ae.path LIKE '/opt/homebrew/%/mariadbd'
  )
  AND NOT (
    signature.identifier = 'netcat'
    AND ae.path LIKE '/Users/%/homebrew/Cellar/netcat/%/bin/netcat'
  )
  AND NOT (
    signature.identifier = 'syncthing'
    AND ae.path LIKE '/nix/store/%-syncthing-%/bin/syncthing'
  )
  AND NOT (
    ae.path LIKE '/Users/%/Library/Application%20Support/Steam/Steam.AppBundle/Steam/'
  )
  AND NOT (
    (
      signature.identifier = 'a.out'
      OR signature.identifier LIKE '%-%'
    )
    AND file.uid > 500
    AND (
      file.directory LIKE '/opt/homebrew/Cellar/%/bin'
      OR file.directory LIKE '/Users/%/bin'
      OR file.directory LIKE '/Users/%/code/%'
      OR file.directory LIKE '/Users/%/src/%'
      OR file.directory LIKE '/Users/%/node_modules/.bin/%'
      OR file.directory LIKE '/Users/%/git/%'
      OR file.directory LIKE '/Users/%/%-cli'
      OR file.directory LIKE '/private/var/folders/%/T/go-build%/exe'
    )
  )
GROUP BY
  exception_key
