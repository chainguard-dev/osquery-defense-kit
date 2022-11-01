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
  AND p.path NOT LIKE '/private/var/folders/%/go-build%/%'
  -- Apple programs running from weird places, like the UpdateBrainService
  AND NOT (
    signature.identifier LIKE 'com.apple.%' AND signature.authority = 'Software Signing'
    AND remote_port IN (53,443,80)
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
    '22,6,500,Cyberduck,ch.sudo.cyberduck,Developer ID Application: David Kocher (G69SCX94XU)',
    '22,6,500,ssh,,',
    '22,6,500,ssh,com.apple.openssh,Software Signing',
    '22,6,500,ssh,com.apple.ssh,Software Signing',
    '22,6,500,ssh,ssh,',
    '22,6,500,ssh,ssh-55554944fbf65684ab9b37c2bad3a27ef78b23f4,',
    '30004,6,500,java,net.java.openjdk.java,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '30011,6,500,java,net.java.openjdk.java,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '32768,6,500,java,net.java.openjdk.java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '3307,6,500,cloud_sql_proxy,a.out,',
    '43,6,500,DropboxMacUpdate,com.dropbox.DropboxMacUpdate,Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    '443,17,500,Code Helper,com.microsoft.VSCode.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,17,500,Evernote Helper,,',
    '443,17,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
    '443,17,500,GitKraken Boards,com.axosoft.glo,Apple iPhone OS Application Signing',
    '443,17,500,Reflect Helper,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    '443,17,500,Slack Helper,,',
    '443,6,0,com.apple.MobileSoftwareUpdate.UpdateBrainService,com.apple.MobileSoftwareUpdate.UpdateBrainService,Software Signing',
    '443,6,0,com.apple.NRD.UpdateBrainService,com.apple.NRD.UpdateBrainService,Software Signing',
    '443,6,0,Install,com.adobe.Install,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,0,launcher,launcher,Developer ID Application: Kolide Inc (YZ3EM74M78)',
    '443,6,0,nessusd,nessusd,Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    '443,6,0,nix,nix,',
    '443,6,0,OneDrivePkgTelemetry,com.microsoft.OneDrivePkgTelemetry,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,0,Setup,com.adobe.acc.Setup,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,500,,,',
    '443,6,500,Acrobat Update Helper,com.adobe.ARMDCHelper,Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    '443,6,500,bash,bash,',
    '443,6,500,chainctl,,',
    '443,6,500,chainctl,a.out,',
    '443,6,500,chainctl,chainctl,',
    '443,6,500,chainctl_Darwin_arm64,a.out,',
    '443,6,500,civo,a.out,',
    '443,6,500,cloud_sql_proxy,a.out,',
    '443,6,500,Code Helper,com.microsoft.VSCode.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,Code Helper (Renderer),com.github.Electron.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,com.docker.backend,com.docker,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,cosign,,',
    '443,6,500,cosign,a.out,',
    '443,6,500,cosign,cosign,',
    '443,6,500,crane,,',
    '443,6,500,crane,a.out,',
    '443,6,500,crane,crane,',
    '443,6,500,ctclient,a.out,',
    '443,6,500,curl,com.apple.curl,Software Signing',
    '443,6,500,darkfiles,a.out,',
    '443,6,500,docker-credential-gcr,a.out,',
    '443,6,500,Electron,com.microsoft.VSCode,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,emacs-28.2,emacs-28.2,',
    '443,6,500,Evernote Helper,,',
    '443,6,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
    '443,6,500,figma_agent,com.figma.agent,Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
    '443,6,500,FlyDelta,com.delta.iphone.ver1,Apple iPhone OS Application Signing',
    '443,6,500,gh,a.out,',
    '443,6,500,gh,gh,',
    '443,6,500,git,com.apple.git,Software Signing',
    '443,6,500,git,git,',
    '443,6,500,GitHub.UI,GitHub,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,GitKraken Boards,com.axosoft.glo,Apple iPhone OS Application Signing',
    '443,6,500,git-remote-http,,',
    '443,6,500,git-remote-http,com.apple.git-remote-http,Software Signing',
    '443,6,500,gitsign,,',
    '443,6,500,gitsign,a.out,',
    '443,6,500,gitsign,gitsign,',
    '443,6,500,go,a.out,',
    '443,6,500,go,org.golang.go,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '443,6,500,grype,grype,',
    '443,6,500,grype,grype,Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)',
    '443,6,500,helm,a.out,',
    '443,6,500,istioctl,a.out,',
    '443,6,500,java,net.java.openjdk.java,Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
    '443,6,500,java,net.java.openjdk.java,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,java,net.java.openjdk.java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '443,6,500,ko,a.out,',
    '443,6,500,ksfetch,ksfetch,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '443,6,500,kubectl,,',
    '443,6,500,kubectl,a.out,',
    '443,6,500,limactl,,',
    '443,6,500,main,a.out,',
    '443,6,500,melange,a.out,',
    '443,6,500,minikube,,',
    '443,6,500,ngrok,darwin_amd64,Developer ID Application: ngrok LLC (TEX8MHRDQ9)',
    '443,6,500,nix,nix,',
    '443,6,500,node,node,Developer ID Application: Node.js Foundation (HX7739G8FX)',
    '443,6,500,old,dev.warp.Warp-Stable,Developer ID Application: Denver Technologies, Inc (2BBY89MBSN)',
    '443,6,500,OneDriveStandaloneUpdater,com.microsoft.OneDriveStandaloneUpdater,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '443,6,500,prober,a.out,',
    '443,6,500,provisio,,',
    '443,6,500,pulumi-resource-gcp,a.out,',
    '443,6,500,pulumi-resource-github,a.out,',
    '443,6,500,python2.7,python2.7,',
    '443,6,500,python3.10,python3.10,',
    '443,6,500,Python,com.apple.python3,Software Signing',
    '443,6,500,Python,org.python.python,',
    '443,6,500,Python,Python,',
    '443,6,500,Reflect,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    '443,6,500,Reflect Helper,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    '443,6,500,release-notes,a.out,',
    '443,6,500,sample,com.apple.dt.SamplingTools.sample,Software Signing',
    '443,6,500,scorecard-darwin-amd64,,',
    '443,6,500,Slack Helper,,',
    '443,6,500,Slack Helper,com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '443,6,500,Slack Helper,com.tinyspeck.slackmacgap.helper,Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)',
    '443,6,500,snyk,snyk_darwin_amd64,Developer ID Application: Snyk Limited (97QYW7LHSF)',
    '443,6,500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '443,6,500,step,step,',
    '443,6,500,sublime_text,com.sublimetext.4,Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    '443,6,500,syft,syft,Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)',
    '443,6,500,terraform-ls,terraform-ls,Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    '443,6,500,terraform,terraform,Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    '443,6,500,trivy,a.out,',
    '443,6,500,vegeta,a.out,',
    '443,6,500,vim,vim,',
    '443,6,500,zoom.us,us.zoom.xos,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    '443,6,500,zsh,com.apple.zsh,Software Signing',
    '53,17,500,docker-credential-gcr,a.out,',
    '53,17,500,trivy,,',
    '6000,6,500,ssh,,',
    '443,17,500,old,dev.warp.Warp-Stable,Developer ID Application: Denver Technologies, Inc (2BBY89MBSN)',
    '6000,6,500,ssh,com.apple.openssh,Software Signing',
    '6000,6,500,ssh,ssh-55554944fbf65684ab9b37c2bad3a27ef78b23f4,',
    '80,6,0,com.apple.MobileSoftwareUpdate.UpdateBrainService,com.apple.MobileSoftwareUpdate.UpdateBrainService,Software Signing',
    '80,6,500,curl,com.apple.curl,Software Signing',
    '80,6,500,ksfetch,ksfetch,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '80,6,500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '80,6,500,webhook.test,a.out,'
  )

  -- There are many signing hashes for git
  AND NOT exception_key LIKE '443,6,500,git-remote-http,git-remote-http-%'
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
    remote_port IN (53, 443)
    AND p.name LIKE 'terraform-provider-%'
  )
  AND NOT (
    remote_port IN (53, 443)
    AND p.name LIKE 'kubectl.%'
  )
  -- Python programs
  AND NOT (
    (p.cmdline LIKE '%google-cloud-sdk/lib/gcloud.py%' OR p.cmdline LIKE '%/opt/homebrew/bin/aws%')
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
GROUP BY
  s.pid
