-- Find programs that use the Security Framework on macOS - popular among malware authors
--
-- platform: darwin
-- tags: persistent state process seldom
SELECT
  s.authority,
  s.identifier,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    p0.name,
    ',',
    s.identifier,
    ',',
    s.authority
  ) AS exception_key,
  pmm.path AS lib_path,
  -- Child
  p0.pid AS p0_pid,
  p0.start_time AS p0_start,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.start_time AS p1_start,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.start_time AS p2_start,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  JOIN process_memory_map pmm ON p0.pid = pmm.pid
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  -- Focus on longer-running programs
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      start_time < (strftime('%s', 'now') - 1200)
      AND parent != 0
      -- Assume STP
      AND NOT path LIKE '/System/%'
      AND NOT path LIKE '/usr/libexec/%'
      AND NOT path LIKE '/usr/sbin/%'
      -- Other oddball binary paths
      AND NOT path LIKE '/opt/homebrew/Cellar/%'
      AND NOT path LIKE '/usr/local/Cellar/%/bin/%'
      AND NOT path LIKE '/Users/%/go/src/%/%.test'
      AND NOT (
        path LIKE '/Users/%/homebrew/Cellar/%'
        AND name IN ('limactl', 'Python', 'bash')
      )
      AND NOT (
        path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/com.elgato.cpu.sdPlugin/cpu'
        AND name = 'cpu'
      )
      AND NOT path IN ('/opt/socket_vmnet/bin/socket_vmnet')
  )
  AND pmm.path LIKE '%Security.framework%'
  AND exception_key NOT IN (
    '0,nix,nix,',
    '0,osqueryd,io.osquery.agent,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    '0,osqueryd,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    '0,velociraptor,a.out,',
    '500,Android File Transfer Agent,com.google.android.mtpagent,Developer ID Application: Google, Inc. (EQHXZ8M8AV)',
    '500,AppleMusic,AppleMusic,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '500,bash,bash,',
    '500,bash,com.apple.bash,Software Signing',
    '500,Bazecor Helper,,',
    '500,Bitwarden,com.bitwarden.desktop,Apple Mac OS Application Signing',
    '500,Bitwarden Helper,com.bitwarden.desktop.helper,Apple Mac OS Application Signing',
    '500,Bitwarden Helper (GPU),com.bitwarden.desktop.helper.GPU,Apple Mac OS Application Signing',
    '500,Bitwarden Helper (Renderer),com.bitwarden.desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,BloomRPC Helper,,',
    '500,bufls,a.out,',
    '500,.cargo-wrapped,.cargo-wrapped,',
    '500,chainctl,a.out,',
    '500,Chromium,Chromium,',
    '500,clangd,clangd,',
    '500,cloud-sql-proxy,a.out,',
    '500,cloud_sql_proxy,a.out,',
    '500,cloud-sql-proxy.darwin.arm64,a.out,',
    '500,copilot-agent-macos-arm64,copilot-agent-macos-arm64-5555494405ae226b796431f588804b65cad1040e,',
    '500,CopyClip,com.fiplab.clipboard,Apple Mac OS Application Signing',
    '500,cosign,a.out,',
    '500,cpu,cpu-555549441132dc6b7af538428ce3359ae94eab37,',
    '500,crane,a.out,',
    '500,debug.test,a.out,',
    '500,dive,a.out,',
    '500,Divvy,com.mizage.Divvy,Apple Mac OS Application Signing',
    '500,dlv,a.out,',
    '500,docker,a.out,',
    '500,Duckly,Electron,',
    '500,Duckly Helper,Electron Helper,',
    '500,Duckly Helper (Renderer),Electron Helper (Renderer),',
    '500,Emacs-arm64-11,Emacs-arm64-11,Developer ID Application: Galvanix (5BRAQAFB8B)',
    '500,epdfinfo,epdfinfo,',
    '500,esbuild,,',
    '500,esbuild,a.out,',
    '500,Evernote,com.evernote.Evernote,Apple Mac OS Application Signing',
    '500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
    '500,Evernote Helper (Renderer),com.evernote.Evernote.helper.Renderer,Apple Mac OS Application Signing',
    '500,fake,a.out,',
    '500,Final Cut Pro,com.apple.FinalCut,Apple Mac OS Application Signing',
    '500,git,git,',
    '500,gitsign,a.out,',
    '500,gitsign-credential-cache,a.out,',
    '500,GitterHelperApp,com.troupe.gitter.mac.GitterHelperApp,Developer ID Application: Troupe Technology Limited (A86QBWJ43W)',
    '500,gke-gcloud-auth-plugin,a.out,',
    '500,go,a.out,',
    '500,gopls,a.out,',
    '500,gopls,gopls,',
    '500,gpg-agent,gpg-agent,',
    '500,Grammarly for Safari,com.grammarly.safari.extension,Apple Mac OS Application Signing',
    '500,Grammarly Safari Extension,com.grammarly.safari.extension.ext2,Apple Mac OS Application Signing',
    '500,hugo,a.out,',
    '500,InternalFiltersXPC,com.apple.InternalFiltersXPC,Apple Mac OS Application Signing',
    '500,ipcserver,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,ipcserver.old,,',
    '500,k9s,a.out,',
    '500,ko,,',
    '500,ko,a.out,',
    '500,kubectl,a.out,',
    '500,lua-language-server,lua-language-server,',
    '500,Magnet,com.crowdcafe.windowmagnet,Apple Mac OS Application Signing',
    '500,mattermost,a.out,',
    '500,Mattermost Helper (GPU),Mattermost.Desktop.helper.GPU,Apple Mac OS Application Signing',
    '500,Mattermost Helper,Mattermost.Desktop.helper,Apple Mac OS Application Signing',
    '500,Mattermost Helper (Renderer),Mattermost.Desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,Mattermost,Mattermost.Desktop,Apple Mac OS Application Signing',
    '500,melange,a.out,',
    '500,melange-run,a.out,',
    '500,monday.com Helper,com.monday.desktop.helper,Apple Mac OS Application Signing',
    '500,monday.com Helper (GPU),com.monday.desktop.helper.GPU,Apple Mac OS Application Signing',
    '500,monday.com Helper (Renderer),com.monday.desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,monorail,a.out,',
    '500,OOPProResRawService,com.apple.videoapps.OOPProResRawService,Apple Mac OS Application Signing',
    '500,osqueryd,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    '500,plugin-darwin-arm64,a.out,',
    '500,PrinterProxy,com.apple.print.PrinterProxy,',
    '500,registry,a.out,',
    '500,registry-redirect,a.out,',
    '500,Runner.Listener,apphost-55554944a938bab90f04347d83659c53dd1197d6,',
    '500,rust-analyzer,rust_analyzer-d11ae4e1bae4360d,',
    '500,scdaemon,scdaemon,',
    '500,sdaudioswitch,,',
    '500,sdaudioswitch,sdaudioswitch,',
    '500,sdzoomplugin,,',
    '500,Slack,com.tinyspeck.slackmacgap,Apple Mac OS Application Signing',
    '500,Slack Helper,com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,Slack Helper (GPU),com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,Slack Helper (Plugin),com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,Slack Helper (Renderer),com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,snyk-ls_darwin_arm64,a.out,',
    '500,ssh,ssh,',
    '500,Steam Helper,com.valvesoftware.steam.helper,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,stern,a.out,',
    '500,syncthing,syncthing,',
    '500,Telegram,ru.keepcoder.Telegram,Apple Mac OS Application Signing',
    '500,testing,com.yourcompany.testing,', -- Xcode iPhone emulator
    '500,tflint,a.out,',
    '500,tflint-ruleset-aws,a.out,',
    '500,tflint-ruleset-google,a.out,',
    '500,timestamp-server,a.out,',
    '500,Todoist,com.todoist.mac.Todoist,Apple Mac OS Application Signing',
    '500,Todoist Helper,com.todoist.mac.Todoist.helper,Apple Mac OS Application Signing',
    '500,Todoist Helper (GPU),com.todoist.mac.Todoist.helper.GPU,Apple Mac OS Application Signing',
    '500,Todoist Helper (Renderer),com.todoist.mac.Todoist.helper.Renderer,Apple Mac OS Application Signing',
    '500,TwitchStudioStreamDeck,TwitchStudioStreamDeck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '500,vim,,',
    '500,vim,vim,',
    '500,WinAppHelper,,',
    '500,WinAppHelper,WinAppHelper,'
  )
  AND NOT (
    exception_key LIKE '500,%,a.out,'
    AND p0.path LIKE '/private/var/folders%/T/go-build%/exe/%'
  )
  AND NOT (
    exception_key LIKE '500,tflint%,a.out,'
    AND p0.path LIKE '/Users/%/.tflint.d/%'
  )
  AND NOT (
    exception_key LIKE '500,python3.%,%,'
    AND p0.path LIKE '/opt/%/bin/python%'
  )
  AND NOT (
    exception_Key LIKE '500,%,a.out,'
    AND p0.path LIKE '/Users/%/go/bin/%'
  )
  AND NOT exception_key LIKE '500,terraform-provider-cosign_%,,'
  AND NOT exception_key LIKE '500,rust-analyzer-aarch64-apple-darwin,rust_analyzer-%,'
  AND NOT exception_key LIKE '500,___Test%.test,a.out,'
  AND NOT exception_key LIKE '500,zellij,zellij%,'
  AND NOT exception_key LIKE '500,copilot-agent-macos-%,copilot-agent-macos-%,'
  AND NOT exception_key LIKE '500,samply,samply-%,'
  AND NOT exception_key LIKE '500,gopls_%,a.out,'
  AND NOT exception_key LIKE '500,terraform-provider-%,a.out,'
  AND NOT exception_key LIKE '500,Runner.%,apphost-%,'
  AND NOT exception_key LIKE '500,kubectl.%,a.out,'
  AND NOT exception_key LIKE '500,marksman-macos,marksman-%,'
  AND NOT exception_key LIKE '500,rustlings,rustlings-%,'
  AND NOT exception_key LIKE '500,rust-analyzer,rust_analyzer-%,'
GROUP BY
  p0.pid
