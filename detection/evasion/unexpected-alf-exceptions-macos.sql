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
WHERE -- Filter out stock exceptions to decrease overhead
  ae.path NOT IN (
    '/System/Library/CoreServices/UniversalControl.app/',
    '/System/Library/PrivateFrameworks/Admin.framework/Versions/A/Resources/readconfig',
    '/System/Library/PrivateFrameworks/EmbeddedOSInstall.framework/Versions/A/XPCServices/EmbeddedOSInstallService.xpc/',
    '/usr/bin/nmblookup',
    '/usr/libexec/bootpd',
    '/usr/libexec/configd',
    '/usr/libexec/discoveryd',
    '/usr/libexec/xartstorageremoted',
    '/usr/sbin/mDNSResponder',
    '/usr/sbin/racoon'
  ) -- Ignore files that ahve already been removed
  AND file.filename NOT NULL
  AND exception_key NOT IN (
    ',,/Applications/Google%20Chrome.app/,',
    ',,/Applications/IntelliJ%20IDEA.app/,',
    ',,/Applications/ProtonMail%20Bridge.app/,',
    ',,/Applications/Visual%20Studio%20Code.app/,',
    ',,/Applications/Visual%20Studio%20Code.app/Contents/Frameworks/Code%20Helper.app/,',
    ',,/Users/cpanato/code/src/github.com/sigstore/docs/node_modules/.bin/hugo/hugo,501',
    ',a.out,/Users/amouat/proj/learning-labs-static/server,501',
    ',a.out,/Users/dlorenc/.wash/downloads/nats-server,501',
    ',a.out,/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin/kubectl,501',
    ',a.out,/opt/homebrew/Cellar/go/1.20.4/libexec/pkg/tool/darwin_arm64/trace,501',
    ',a.out,/private/tmp/learning-labs-static/server,501',
    ',dnsmasq,/opt/homebrew/Cellar/dnsmasq/2.88/sbin/dnsmasq,0',
    ',iodined-55554944d1ffcb236a84363d9b667be6a1742a17,/usr/local/sbin/iodined,501',
    ',java,/opt/homebrew/Cellar/openjdk/19/libexec/openjdk.jdk/Contents/Home/bin/java,501',
    '/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/',
    'Apple Mac OS Application Signing,com.anydo.mac,/Applications/Anydo.app/,0',
    'Apple Mac OS Application Signing,com.apple.garageband10,/Applications/GarageBand.app/,0',
    'Apple Mac OS Application Signing,com.busymac.busycal3,/Applications/BusyCal.app/,0',
    'Apple Mac OS Application Signing,com.evernote.Evernote,/Applications/Evernote.app/,0',
    'Apple Mac OS Application Signing,com.joeallen.teleprompter.mac,/Applications/Teleprompter.app/,0',
    'Apple Mac OS Application Signing,com.utmapp.QEMULauncher,/Applications/UTM.app/Contents/XPCServices/QEMUHelper.xpc/Contents/MacOS/QEMULauncher.app/,0',
    'Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension,/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/,0',
    'Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension,/Applications/Tailscale.localized/Tailscale.app/Contents/PlugIns/IPNExtension.appex/,0',
    'Developer ID Application: Adguard Software Limited (TC3Q7MAJXF),com.adguard.mac.adguard.network-extension,/Library/SystemExtensions/AD3BCA34-237A-4135-B7A4-0F7477D9144C/com.adguard.mac.adguard.network-extension.systemextension/,0',
    'Developer ID Application: Any.DO inc. (FW4RAPJ9FF),com.anydo.mac,/Applications/Anydo.app/,501',
    'Developer ID Application: Bearly Inc (NK6K4BACCF),com.bearly.app,/Applications/Bearly.app/,501',
    'Developer ID Application: Bohemian Coding (WUGMZZ5K46),com.bohemiancoding.SketchMirrorHelper,/Applications/Sketch.app/Contents/XPCServices/SketchMirrorHelper.xpc/,501',
    'Developer ID Application: Bohemian Coding (WUGMZZ5K46),com.bohemiancoding.sketch3,/Applications/Sketch.app/,501',
    'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW),com.brother.utility.WorkflowAppControlServer,/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/,0',
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59),com.canonical.multipass.,/Applications/Multipass.app/,0',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5),com.elgato.WaveLink,/Applications/WaveLink.app/,0',
    'Developer ID Application: Crul, Inc. (5PTD6R25S6),com.electron.crul,/Applications/crul.app/,501',
    'Developer ID Application: DBeaver Corporation (42B6MDKMW8),org.jkiss.dbeaver.core.product,/Applications/DBeaver.app/,501',
    'Developer ID Application: Docker Inc (9BNSXJN65R),com.docker.docker,/Applications/Docker.app/,501',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK),com.getdropbox.dropbox,/Applications/Dropbox.app/,501',
    'Developer ID Application: Evernote Corporation (Q79WDW8YH9),com.evernote.Evernote,/Applications/Evernote.app/,501',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.goland,/Applications/GoLand.app/,501',
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.pycharm,/Applications/PyCharm.app/,501',
    'Developer ID Application: Loom, Inc (QGD2ZPXZZG),com.loom.desktop,/Applications/Loom.app/,501',
    'Developer ID Application: Martijn Smit (GX645XXEAX),com.mutedeck.mac,/Applications/MuteDeck/MuteDeck.app/,501',
    'Developer ID Application: Opentest, Inc. (QGD2ZPXZZG),com.loom.desktop,/Applications/Loom.app/,501',
    'Developer ID Application: Postdot Technologies, Inc (H7H8Q7M5CK),com.postmanlabs.mac,/Applications/Postman.app/,501',
    'Developer ID Application: Python Software Foundation (BMM5U3QVKW),org.python.python,/Library/Frameworks/Python.framework/Versions/3.11/Resources/Python.app/,0',
    'Developer ID Application: Python Software Foundation (BMM5U3QVKW),org.python.python,/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/,0',
    'Developer ID Application: Raycast Technologies Inc (SY64MV22J9),com.raycast.macos,/Applications/Raycast.app/,501',
    'Developer ID Application: RescueTime, Inc (FSY4RB8H39),c]om.rescuetime.RescueTime,/Applications/RescueTime.app/,0',
    'Developer ID Application: Sonos, Inc. (2G4LW83Q3E),com.sonos.macController,/Applications/Sonos.app/,501',
    'Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client,/Applications/Spotify.app/,501',
    'Developer ID Application: Tailscale Inc. (W5364U7YZB),io.tailscale.ipn.macsys.network-extension,/Library/SystemExtensions/A30AF854-E980-4345-A658-17000BF66D00/io.tailscale.ipn.macsys.network-extension.systemextension/,0',
    'Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM),com.vng.zalo,/Applications/Zalo.app/,501',
    'Developer ID Application: Voicemod Sociedad Limitada. (S2MC4XQDSM),net.voicemod.desktop,/Applications/Voicemod.app/,0',
    'Developer ID Application: Zed Industries, Inc. (MQ55VZLNZQ),dev.zed.Zed,/Applications/Zed.app/,501',
    'Developer ID Application: Zed Industries, Inc. (MQ55VZLNZQ),dev.zed.Zed,/Volumes/Zed/Zed.app/,501',
    'Software Signing,com.apple.Music,/System/Applications/Music.app/,0',
    'Software Signing,com.apple.Terminal,/System/Applications/Utilities/Terminal.app/,0',
    'Software Signing,com.apple.WebKit.Networking,/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/,0',
    'Software Signing,com.apple.WebKit.Networking,/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/,0',
    'Software Signing,com.apple.audio.AUHostingService.arm64e,/System/Library/Frameworks/AudioToolbox.framework/XPCServices/AUHostingServiceXPC_arrow.xpc/,0',
    'Software Signing,com.apple.audio.AUHostingService.x86-64,/System/Library/Frameworks/AudioToolbox.framework/XPCServices/AUHostingServiceXPC.xpc/,0',
    'Software Signing,com.apple.audio.InfoHelper,/System/Library/Frameworks/AudioToolbox.framework/XPCServices/com.apple.audio.InfoHelper.xpc/,0',
    'Software Signing,com.apple.controlcenter,/System/Library/CoreServices/ControlCenter.app/,0',
    'Software Signing,com.apple.nc,/usr/bin/nc,0',
    'Software Signing,com.apple.netbiosd,/usr/sbin/netbiosd,0',
    'Software Signing,com.apple.python3,/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/,0',
    'Software Signing,com.apple.python3,/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/,0',
    'Software Signing,com.apple.rapportd,/usr/libexec/rapportd,0',
    'Software Signing,com.apple.rpc,/usr/sbin/rpc.lockd,0',
    'Software Signing,com.apple.xartstorageremoted,/usr/libexec/xartstorageremoted,0',
    'qbittorrent macos,org.qbittorrent.qBittorrent,/Applications/qbittorrent.app/,501'
  )
  AND NOT exception_key LIKE ',a.out,/Users/%/dev/%,501'
  AND NOT exception_key LIKE ',a.out,/Users/%/hugo,501'
  AND NOT exception_key LIKE 'Developer ID Application: Cypress.Io, Inc. (7D655LWGLY),com.electron.cypress,/Users/%/Library/Caches/Cypress/13.12.0/Cypress.app/,501'
  AND NOT exception_key LIKE 'Developer ID Application: The Foundry (82R497YNSK),org.python.python,/Applications/Nuke%/Contents/Frameworks/Python.framework/Versions/%/Resources/Python.app/,501'
  AND NOT exception_key LIKE ',org.python.python,/opt/homebrew/Cellar/python%/Frameworks/Python.framework/Versions/%/Resources/Python.app/,501'
  AND NOT exception_key LIKE ',git-daemon-%,/opt/homebrew/Cellar/git/%/libexec/git-core/git-daemon,501'
  AND NOT exception_key LIKE ',org.python.python,/opt/homebrew/Cellar/python@%/Frameworks/Python.framework/Versions/3.11/Resources/Python.app/,501'
  AND NOT exception_key LIKE ',a.out,/opt/homebrew/Cellar/podman/%/libexec/podman/gvproxy,501'
  AND NOT exception_key LIKE ',net.java.openjdk.java,/opt/homebrew/Cellar/openjdk%/libexec/openjdk.jdk/Contents/Home/bin/java,501'
  AND NOT exception_key LIKE ',a.out,/private/var/folders/%/T/GoLand/%,501'
  AND NOT exception_key LIKE ',a.out,/Users/%/GolandProjects/documentation-code-examples/debuggingTutorial/myApp,501'
  AND NOT exception_key LIKE ',node,/opt/homebrew/Cellar/nvm/%/versions/node/v%/bin/node,501'
  AND NOT exception_key LIKE ',java,/opt/homebrew/Cellar/openjdk/%/libexec/openjdk.jdk/Contents/Home/bin/java,501'
  AND NOT exception_key LIKE ',python3.%,/nix/store/%-python3-3%/bin/python3.%,0'
  AND NOT signature.authority IN (
    'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    'Developer ID Application: The Foundry (82R497YNSK)',
    'Developer ID Application: OpenAI, L.L.C. (2DC432GLL2)'
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
    signature.identifier = 'nix'
    AND ae.path LIKE '/nix/store/%-nix-%/bin/nix'
  )
  AND NOT (
    ae.path LIKE '/Users/%/Library/Application%20Support/Steam/Steam.AppBundle/Steam/'
  )
  AND NOT (
    signature.authority = ''
    AND signature.identifier = 'org.chromium.Chromium'
    AND ae.path LIKE '/Users/%/Library/pnpm/global/%/.pnpm/carlo@%/node_modules/carlo/lib/.local-data/mac-%/chrome-mac/Chromium.app/'
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
      OR file.directory LIKE '/Users/%/gh/%'
      OR file.directory LIKE '/Users/%/debug/%'
      OR file.directory LIKE '/Users/%/target/%'
      OR file.directory LIKE '/Users/%/tmp/%'
      OR file.directory LIKE '/Users/%/sigstore/%'
      OR file.directory LIKE '/Users/%/node_modules/.bin/%'
      OR file.directory LIKE '/Users/%/git/%'
      OR file.directory LIKE '/Users/%/%-cli'
      OR file.directory LIKE '/private/var/folders/%/T/go-build%/exe'
    )
  )
GROUP BY
  exception_key
