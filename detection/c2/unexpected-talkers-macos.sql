-- Programs communicating over the network in unexpected ways (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net often
-- platform: darwin
SELECT
  protocol,
  s.local_port,
  s.remote_port,
  s.remote_address,
  s.local_port,
  s.local_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  s.pid,
  p.parent AS parent_pid,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  hash.sha256,
  CONCAT (
    MIN(s.remote_port, 32768),
    ',',
    protocol,
    ',',
    MIN(p.uid, 500),
    ',',
    p.name,
    ',',
    signature.identifier,
    ',',
    signature.authority
  ) AS exception_key
FROM
  process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON pp.pid = p.parent
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE
  protocol > 0
  AND s.remote_port > 0
  AND s.remote_address NOT IN ('127.0.0.1', '::ffff:127.0.0.1', '::1')
  AND s.remote_address NOT LIKE 'fe80:%'
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND s.state != 'LISTEN' -- Ignore most common application paths
  AND p.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p.path NOT LIKE '/Library/Apple/System/Library/%'
  AND p.path NOT LIKE '/Library/Application Support/%/Contents/%'
  AND p.path NOT LIKE '/System/Applications/%'
  AND p.path NOT LIKE '/System/Library/%'
  AND p.path NOT LIKE '/Users/%/Library/%.app/Contents/MacOS/%'
  AND p.path NOT LIKE '/Users/%/code/%'
  AND p.path NOT LIKE '/Users/%/src/%'
  AND p.path NOT LIKE '/Users/%/bin/%'
  AND p.path NOT LIKE '/System/%'
  AND p.path NOT LIKE '/opt/homebrew/Cellar/%/bin/%'
  AND p.path NOT LIKE '/usr/libexec/%'
  AND p.path NOT LIKE '/usr/sbin/%'
  AND p.path NOT LIKE '/usr/local/kolide-k2/bin/%'
  AND p.path NOT LIKE '/private/var/folders/%/go-build%/%'
  -- Apple programs running from weird places, like the UpdateBrainService
  AND NOT (
    signature.identifier LIKE 'com.apple.%'
    AND signature.authority = 'Software Signing'
    AND remote_port IN (53, 443, 80)
    AND protocol IN (6, 17)
  )
  AND NOT (
    remote_port = 53
    AND protocol IN (6, 17)
    AND p.name IN (
      '1password',
      'Acrobat Update Helper',
      'chainctl',
      'cloud_sql_proxy',
      'Code Helper',
      'com.apple.MobileSoftwareUpdate.UpdateBrainService',
      'cosign',
      'crc',
      'curl',
      'dig',
      'Evernote Helper',
      'figma_agent',
      'gh',
      'git-remote-http',
      'gitsign',
      'go',
      'grafana-server',
      'grype',
      'host',
      'htop',
      'istioctl',
      'k6',
      'k9s',
      'ko',
      'launcher',
      'ngrok',
      'nix',
      'node',
      'obs',
      'obs-browser-page',
      'obs-ffmpeg-mux',
      'obsidian',
      'opera',
      'ping',
      'Python',
      'python3.10',
      'Reflect',
      'Reflect Helper',
      'ruby',
      'sample',
      'Signal Helper',
      'ssh',
      'steam_osx',
      'syncthing',
      'tailscaled',
      'terraform',
      'tkn',
      'traceroute',
      'vcluster',
      'wget',
      'whois',
      'zoom'
    )
  )
  AND NOT exception_key IN (
    '123,17,500,gvproxy,,',
    '123,17,500,gvproxy,a.out,',
    '22,6,500,Cyberduck,ch.sudo.cyberduck,Developer ID Application: David Kocher (G69SCX94XU)',
    '22,6,500,ssh,,',
    '22,6,500,ssh,com.apple.openssh,Software Signing',
    '22,6,500,ssh,com.apple.ssh,Software Signing',
    '22,6,500,ssh,ssh,',
    '22,6,500,ssh,ssh-55554944fbf65684ab9b37c2bad3a27ef78b23f4,',
    '30004,6,500,java,net.java.openjdk.java,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '30011,6,500,java,net.java.openjdk.java,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '31580,6,500,kubectl.1.23,a.out,',
    '32768,6,500,java,net.java.openjdk.java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '3307,6,500,cloud_sql_proxy,a.out,',
    '43,6,500,DropboxMacUpdate,com.dropbox.DropboxMacUpdate,Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    '443,17,500,Code Helper,com.microsoft.VSCode.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,17,500,Evernote Helper,,',
    '443,17,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
    '443,17,500,GitKraken Boards,com.axosoft.glo,Apple iPhone OS Application Signing',
    '443,17,500,old,dev.warp.Warp-Stable,Developer ID Application: Denver Technologies, Inc (2BBY89MBSN)',
    '443,17,500,Reflect Helper,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    '443,17,500,Signal Helper,org.whispersystems.signal-desktop.helper,Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '443,17,500,Slack Helper,,',
    '443,17,500,Slack Helper,com.tinyspeck.slackmacgap.helper,Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)',
    '443,6,0,Adobe Installer,com.adobe.AAMHelper,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,0,com.apple.MobileSoftwareUpdate.UpdateBrainService,com.apple.MobileSoftwareUpdate.UpdateBrainService,Software Signing',
    '443,6,0,com.apple.NRD.UpdateBrainService,com.apple.NRD.UpdateBrainService,Software Signing',
    '443,6,0,com.paragon-software.extfsd,com.paragon-software.extfsd,Developer ID Application: Paragon Software GmbH (LSJ6YVK468)', -- update checks
    '443,6,0,com.paragon-software.ntfsd,com.paragon-software.ntfsd,Developer ID Application: Paragon Software GmbH (LSJ6YVK468)', -- update checks
    '443,6,0,Install,com.adobe.cc.Install,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,0,Install,com.adobe.Install,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,0,io.tailscale.ipn.macsys.network-extension,io.tailscale.ipn.macsys.network-extension,Developer ID Application: Tailscale Inc. (W5364U7YZB)',
    '443,6,0,kandji-daemon,kandji-daemon,Developer ID Application: Kandji, Inc. (P3FGV63VK7)',
    '443,6,0,launcher,com.kolide.agent,Developer ID Application: Kolide, Inc (X98UFR7HA3)',
    '443,6,0,launcher,launcher,Developer ID Application: Kolide, Inc (X98UFR7HA3)',
    '443,6,0,launcher,launcher,Developer ID Application: Kolide Inc (YZ3EM74M78)',
    '443,6,0,nessusd,nessusd,Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    '443,6,0,nix,nix,',
    '443,6,0,OneDrivePkgTelemetry,com.microsoft.OneDrivePkgTelemetry,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,0,Setup,com.adobe.acc.Setup,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,307,curl,curl,',
    '443,6,500,,,',
    '443,6,500,Acrobat Update Helper,com.adobe.ARMDCHelper,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,500,Amazon Photos Installer,com.amazon.clouddrive.mac.installer,Developer ID Application: AMZN Mobile LLC (94KV3E626L)',
    '443,6,500,apko,a.out,',
    '443,6,500,aws,37c466-aws,Developer ID Application: AMZN Mobile LLC (94KV3E626L)',
    '443,6,500,aws,e956a0-aws,Developer ID Application: AMZN Mobile LLC (94KV3E626L)',
    '443,6,500,bash,bash,',
    '443,6,500,BlockBlock Installer,com.objective-see.blockblock.installer,Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    '443,6,500,bom,,',
    '443,6,500,chainctl,,',
    '443,6,500,chainctl,a.out,',
    '443,6,500,chainctl,chainctl,',
    '443,6,500,chainctl_darwin_arm64,a.out,',
    '443,6,500,chainctl_Darwin_arm64,a.out,',
    '443,6,500,cilium,,',
    '443,6,500,civo,a.out,',
    '443,6,500,cloud_sql_proxy,a.out,',
    '443,6,500,Code Helper,com.microsoft.VSCode.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,Code Helper (Plugin),com.github.Electron.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,Code Helper (Renderer),com.github.Electron.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,com.docker.backend,com.docker,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,com.docker.extensions,com.docker,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,cosign,,',
    '443,6,500,cosign,a.out,',
    '443,6,500,cosign,cosign,',
    '443,6,500,cpu,cpu-555549441132dc6b7af538428ce3359ae94eab37,',
    '443,6,500,crane,,',
    '443,6,500,crane,a.out,',
    '443,6,500,crane,crane,',
    '443,6,500,ctclient,a.out,',
    '443,6,500,curl,com.apple.curl,Software Signing',
    '443,6,500,darkfiles,a.out,',
    '443,6,500,docker-credential-gcr,a.out,',
    '443,6,500,Docker Desktop Helper,com.electron.dockerdesktop.helper,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,docker-index,docker-index,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,Electron,com.microsoft.VSCode,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,emacs-28.2,emacs-28.2,',
    '443,6,500,Evernote Helper,,',
    '443,6,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
    '443,6,500,figma_agent,com.figma.agent,Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
    '443,6,500,FlyDelta,com.delta.iphone.ver1,Apple iPhone OS Application Signing',
    '443,6,500,FOX Sports Helper,Electron Helper,',
    '443,6,500,gh,a.out,',
    '443,6,500,gh,gh,',
    '443,6,500,gh-sbom,gh-sbom-b3d347c0b2c99e6c265dff64210a79ddfac85a72,',
    '443,6,500,git,com.apple.git,Software Signing',
    '443,6,500,git-credential-manager,git-credential-manager,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,git-credential-osxkeychain,git-credential-osxkeychain,',
    '443,6,500,git,git,',
    '443,6,500,GitHub Desktop Helper,com.github.GitHubClient.helper,Developer ID Application: GitHub (VEKTX9H2N7)',
    '443,6,500,GitHub.UI,GitHub,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,GitKraken Boards,com.axosoft.glo,Apple iPhone OS Application Signing',
    '443,6,500,git-remote-http,,',
    '443,6,500,git-remote-http,com.apple.git-remote-http,Software Signing',
    '443,6,500,git-remote-http,git-remote-http,',
    '443,6,500,gitsign,,',
    '443,6,500,gitsign,a.out,',
    '443,6,500,gitsign,gitsign,',
    '443,6,500,go,,',
    '443,6,500,go,a.out,',
    '443,6,500,go,org.golang.go,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '443,6,500,grype,grype,',
    '443,6,500,grype,grype,Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)',
    '443,6,500,gvproxy,a.out,',
    '443,6,500,helm,,',
    '443,6,500,helm,a.out,',
    '443,6,500,Install,com.adobe.cc.Install,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,500,istioctl,a.out,',
    '443,6,500,java,net.java.openjdk.java,Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
    '443,6,500,java,net.java.openjdk.java,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,java,net.java.openjdk.java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '443,6,500,Java Updater,com.oracle.java.Java-Updater,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '443,6,500,jx,,',
    '443,6,500,Kindle,com.amazon.Lassen,TestFlight Beta Distribution',
    '443,6,500,ko,a.out,',
    '443,6,500,ksfetch,ksfetch,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '443,6,500,kubectl,,',
    '443,6,500,kubectl,a.out,',
    '443,6,500,legitify,legitify,Developer ID Application: LEGIT SECURITY LTD (8V693922X7)',
    '443,6,500,limactl,,',
    '443,6,500,main,a.out,',
    '443,6,500,mconvert,a.out,',
    '443,6,500,melange,a.out,',
    '443,6,500,minikube,,',
    '443,6,500,ngrok,darwin_amd64,Developer ID Application: ngrok LLC (TEX8MHRDQ9)',
    '443,6,500,nix,nix,',
    '443,6,500,node,node,Developer ID Application: Node.js Foundation (HX7739G8FX)',
    '443,6,500,old,dev.warp.Warp-Stable,Developer ID Application: Denver Technologies, Inc (2BBY89MBSN)',
    '443,6,500,OneDriveStandaloneUpdater,com.microsoft.OneDriveStandaloneUpdater,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,op,com.1password.op,Developer ID Application: AgileBits Inc. (2BUA8C4S2C)',
    '443,6,500,Paintbrush,com.soggywaffles.paintbrush,Developer ID Application: Michael Schreiber (G966ML7VBG)',
    '443,6,500,PlexMobile,com.plexapp.plex,Apple iPhone OS Application Signing',
    '443,6,500,policy-tester,a.out,',
    '443,6,500,prober,a.out,',
    '443,6,500,provisio,,',
    '443,6,500,pulumi-resource-gcp,a.out,',
    '443,6,500,pulumi-resource-github,a.out,',
    '443,6,500,python2.7,python2.7,',
    '443,6,500,python3.10,python3.10,',
    '443,6,500,Python,com.apple.python3,Software Signing',
    '443,6,500,Python,org.python.python,',
    '443,6,500,Python,Python,',
    '443,6,500,rclone,a.out,',
    '443,6,500,Reflect,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    '443,6,500,Reflect Helper,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    '443,6,500,release-notes,a.out,',
    '443,6,500,sample,com.apple.dt.SamplingTools.sample,Software Signing',
    '443,6,500,scorecard-darwin-amd64,,',
    '443,6,500,sdaudioswitch,,',
    '443,6,500,sdaudioswitch,sdaudioswitch,',
    '443,6,500,sdzoomplugin,,',
    '443,6,500,Signal Helper,org.whispersystems.signal-desktop.helper,Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '443,6,500,Signal Helper (Renderer),org.whispersystems.signal-desktop.helper.Renderer,Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '443,6,500,Signal,org.whispersystems.signal-desktop,Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '443,6,500,Slack Helper,,',
    '443,6,500,Slack Helper,com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '443,6,500,Slack Helper,com.tinyspeck.slackmacgap.helper,Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)',
    '443,6,500,snyk,snyk_darwin_amd64,Developer ID Application: Snyk Limited (97QYW7LHSF)',
    '443,6,500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '443,6,500,steampipe-plugin-aws.plugin,a.out,',
    '443,6,500,step,step,',
    '443,6,500,sublime_text,com.sublimetext.4,Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    '443,6,500,syft,syft,Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)',
    '443,6,500,terraform-ls,terraform-ls,Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    '443,6,500,terraform,terraform,Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    '443,6,500,Transmit,com.panic.Transmit,Developer ID Application: Panic, Inc. (VE8FC488U5)',
    '443,6,500,trivy,,',
    '443,6,500,trivy,a.out,',
    '443,6,500,TwitchStudioStreamDeck,TwitchStudioStreamDeck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '443,6,500,vegeta,a.out,',
    '443,6,500,vim,vim,',
    '443,6,500,wolfictl,a.out,',
    '443,6,500,zoom.us,us.zoom.xos,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    '443,6,500,zsh,com.apple.zsh,Software Signing',
    '53,17,500,docker-credential-gcr,a.out,',
    '53,17,500,trivy,,',
    '6000,6,500,ssh,,',
    '6000,6,500,ssh,com.apple.openssh,Software Signing',
    '6000,6,500,ssh,ssh-55554944fbf65684ab9b37c2bad3a27ef78b23f4,',
    '80,6,0,com.apple.MobileSoftwareUpdate.UpdateBrainService,com.apple.MobileSoftwareUpdate.UpdateBrainService,Software Signing',
    '80,6,0,com.google.one.NetworkExtension,com.google.one.NetworkExtension,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '80,6,500,curl,com.apple.curl,Software Signing',
    '80,6,500,ksfetch,ksfetch,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '80,6,500,mconvert,a.out,',
    '80,6,500,ngrok,darwin_amd64,Developer ID Application: ngrok LLC (TEX8MHRDQ9)',
    '80,6,500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '80,6,500,webhook.test,a.out,',
    '8801,17,500,zoom.us,us.zoom.xos,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    '9418,6,500,git,com.apple.git,Software Signing'

  )
  AND NOT exception_key LIKE '443,6,500,java,com.oracle.java.%.java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)'
  AND NOT exception_key LIKE '27%,6,500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)'
  AND NOT exception_key LIKE '443,6,500,ZwiftAppMetal,ZwiftAppMetal-%,%'
  AND NOT exception_key LIKE '80,6,500,ZwiftAppMetal,ZwiftAppMetal-%,%'
  AND NOT exception_key LIKE '443,6,500,git-remote-http,git-remote-http-%'
  AND NOT exception_key LIKE '443,6,500,cargo,cargo-%'
  -- aws
  AND NOT exception_key LIKE '443,6,500,aws,%-aws,Developer ID Application: AMZN Mobile LLC (94KV3E626L)'
  -- Github actions-runner
  AND NOT exception_key LIKE '443,6,500,Runner.Worker,apphost-%'
  AND NOT exception_key LIKE '443,6,500,Runner.Listener,apphost-%'
  AND NOT exception_key LIKE '443,6,500,gh-dash,gh-dash-%,'
  --
  -- nix-shell infects children with open connections
  AND NOT (
    parent_cmd LIKE '%/tmp/nix-shell%'
    AND remote_port = 443
    AND protocol = 6
  ) -- These programs would normally never make an outgoing connection, but thanks to Nix, it can happen.
  AND NOT (
    (
      remote_address LIKE '151.101.%'
      OR remote_address LIKE '140.82.%'
      OR remote_address LIKE '199.232.%'
    )
    AND remote_port = 443
    AND protocol = 6
    AND (
      pp.path LIKE '/nix/store/%'
      OR p.path LIKE '/nix/store/%'
    )
  ) -- More complicated patterns go here
  AND NOT (
    p.name = 'syncthing'
    AND (
      remote_port IN (53, 80, 88, 110, 443, 587, 993)
      OR remote_port > 1024
    )
  )
  AND NOT (
    p.name IN (
      'Google Chrome Helper',
      'Brave Browser Helper',
      'Chromium Helper',
      'Opera Helper'
    )
    AND remote_port IN (
      53,
      443,
      80,
      8009,
      8080,
      8888,
      8443,
      5228,
      32211,
      53,
      10001,
      3478,
      19305,
      19306,
      5004,
      9000,
      19307,
      19308,
      19309
    )
  )
  AND NOT (
    p.name IN ('Mail', 'thunderbird', 'Spark', 'Notes')
    AND remote_port IN (53, 143, 443, 587, 465, 585, 993)
  )
  AND NOT (
    parent_path = '/Applications/Minecraft.app/Contents/MacOS/launcher'
    AND remote_port > 30000
  )
  AND NOT (
    p.name IN ('Spotify Helper', 'Spotify')
    AND remote_port IN (53, 443, 8009, 4070, 32211)
  )
  AND NOT (
    remote_port IN (53, 80, 443)
    AND p.name LIKE 'terraform-provider-%'
  )
  AND NOT (
    remote_port IN (53, 443)
    AND p.name LIKE 'kubectl%'
  )
  -- Python programs
  AND NOT (
    (
      p.cmdline LIKE '%google-cloud-sdk/lib/gcloud.py%'
      OR p.cmdline LIKE '%/opt/homebrew/bin/aws%'
    )
    AND remote_port IN (80, 443, 53)
  ) -- Slack update?
  AND NOT (
    p.path = ''
    AND pp.cmdline LIKE '%/Slack'
  ) -- Process name is sometimes empty here?
  AND NOT (
    p.cmdline = '/Applications/Craft.app/Contents/MacOS/Craft'
    AND remote_port = 443
    AND protocol = 6
  )
  AND NOT (
    remote_port IN (53, 443)
    AND p.path LIKE '/private/var/folders/%/T/GoLand/%'
  )
  -- theScore and other iPhone apps
  AND NOT (
    remote_port = 443
    AND signature.authority = 'Apple iPhone OS Application Signing'
    AND p.cwd = '/'
    AND p.path = '/private/var/folders/%/Wrapper/%.app/%'
  )
GROUP BY
  s.pid
