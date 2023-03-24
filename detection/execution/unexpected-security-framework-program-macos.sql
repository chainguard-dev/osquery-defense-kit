-- Find programs that use the Security Framework on macOS - popular among malware authors
--
-- platform: darwin
-- tags: persistent state process
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
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
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
      start_time < (strftime('%s', 'now') - 3600)
      AND parent != 0
      -- Assume STP
      AND NOT path LIKE '/System/%'
      AND NOT path LIKE '/usr/libexec/%'
      AND NOT path LIKE '/usr/sbin/%'
      -- Other oddball binary paths
      AND NOT path LIKE '/opt/homebrew/Cellar/%'
      AND NOT path LIKE '/usr/local/Cellar/%/bin/%'
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
    '0,osqueryd,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    '500,bash,com.apple.bash,Software Signing',
    '500,Bitwarden,com.bitwarden.desktop,Apple Mac OS Application Signing',
    '500,Bitwarden Helper,com.bitwarden.desktop.helper,Apple Mac OS Application Signing',
    '500,Bitwarden Helper (GPU),com.bitwarden.desktop.helper.GPU,Apple Mac OS Application Signing',
    '500,Bitwarden Helper (Renderer),com.bitwarden.desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,bufls,a.out,',
    '500,stern,a.out,',
    '500,registry,a.out,',
    '500,mattermost,a.out,',
    '500,plugin-darwin-arm64,a.out,',
    '500,testing,com.yourcompany.testing,', -- Xcode iPhone emulator
    '500,.cargo-wrapped,.cargo-wrapped,',
    '500,cloud_sql_proxy,a.out,',
    '500,CopyClip,com.fiplab.clipboard,Apple Mac OS Application Signing',
    '500,cosign,a.out,',
    '500,hugo,a.out,',
    '500,chainctl,a.out,',
    '500,cpu,cpu-555549441132dc6b7af538428ce3359ae94eab37,',
    '500,Divvy,com.mizage.Divvy,Apple Mac OS Application Signing',
    '500,Emacs-arm64-11,Emacs-arm64-11,Developer ID Application: Galvanix (5BRAQAFB8B)',
    '500,epdfinfo,epdfinfo,',
    '500,esbuild,a.out,',
    '500,fake,a.out,',
    '500,Final Cut Pro,com.apple.FinalCut,Apple Mac OS Application Signing',
    '500,gitsign-credential-cache,a.out,',
    '500,GitterHelperApp,com.troupe.gitter.mac.GitterHelperApp,Developer ID Application: Troupe Technology Limited (A86QBWJ43W)',
    '500,gopls,a.out,',
    '500,gopls,gopls,',
    '500,dive,a.out,',
    '500,snyk-ls_darwin_arm64,a.out,',
    '500,gpg-agent,gpg-agent,',
    '500,InternalFiltersXPC,com.apple.InternalFiltersXPC,Apple Mac OS Application Signing',
    '500,ipcserver,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,ipcserver.old,,',
    '500,debug.test,a.out,',
    '500,Bazecor Helper,,',
    '500,ko,a.out,',
    '500,kubectl,a.out,',
    '500,lua-language-server,lua-language-server,',
    '500,Magnet,com.crowdcafe.windowmagnet,Apple Mac OS Application Signing',
    '500,Mattermost Helper (GPU),Mattermost.Desktop.helper.GPU,Apple Mac OS Application Signing',
    '500,Mattermost Helper,Mattermost.Desktop.helper,Apple Mac OS Application Signing',
    '500,Mattermost Helper (Renderer),Mattermost.Desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,Mattermost,Mattermost.Desktop,Apple Mac OS Application Signing',
    '500,osqueryd,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    '500,PrinterProxy,com.apple.print.PrinterProxy,',
    '500,BloomRPC Helper,,',
    '500,melange-run,a.out,',
    '500,dlv,a.out,',
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
    '500,Steam Helper,com.valvesoftware.steam.helper,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,syncthing,syncthing,',
    '500,Telegram,ru.keepcoder.Telegram,Apple Mac OS Application Signing',
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
  AND NOT exception_key LIKE '500,terraform-provider-%,a.out,'
  AND NOT exception_key LIKE '500,Runner.%,apphost-%,'
  AND NOT exception_key LIKE '500,kubectl.%,a.out,'
  AND NOT exception_key LIKE '500,rustlings,rustlings-%,'
  AND NOT exception_key LIKE '500,rust-analyzer,rust_analyzer-%,'
GROUP BY
  p0.pid
