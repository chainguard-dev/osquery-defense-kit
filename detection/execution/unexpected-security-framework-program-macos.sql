-- Find programs that use the Security Framework on macOS - popular among malware authors
--
-- platform: macos
-- tags: persistent state process
SELECT
  pmm.pid,
  pmm.path AS lib_path,
  p.path,
  p.name,
  p.cmdline,
  p.cwd,
  p.euid,
  p.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256,
  CONCAT (
    MIN(p.euid, 500),
    ',',
    p.name,
    ',',
    s.identifier,
    ',',
    s.authority
  ) AS exception_key
FROM
  processes p
  LEFT JOIN process_memory_map pmm ON p.pid = pmm.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
  LEFT JOIN signature s ON p.path = s.path
WHERE
  lib_path LIKE '%Security.framework%'
  AND exception_key NOT IN (
    '0,nix,nix,',
    '0,osqueryd,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    '500,Bitwarden,com.bitwarden.desktop,Apple Mac OS Application Signing',
    '500,Bitwarden Helper,com.bitwarden.desktop.helper,Apple Mac OS Application Signing',
    '500,Bitwarden Helper (GPU),com.bitwarden.desktop.helper.GPU,Apple Mac OS Application Signing',
    '500,Bitwarden Helper (Renderer),com.bitwarden.desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,bufls,a.out,',
    '500,.cargo-wrapped,.cargo-wrapped,',
    '500,cloud_sql_proxy,a.out,',
    '500,cosign,a.out,',
    '500,cpu,cpu-555549441132dc6b7af538428ce3359ae94eab37,',
    '500,Emacs-arm64-11,Emacs-arm64-11,Developer ID Application: Galvanix (5BRAQAFB8B)',
    '500,epdfinfo,epdfinfo,',
    '500,esbuild,a.out,',
    '500,fake,a.out,',
    '500,Final Cut Pro,com.apple.FinalCut,Apple Mac OS Application Signing',
    '500,gitsign-credential-cache,a.out,',
    '500,GitterHelperApp,com.troupe.gitter.mac.GitterHelperApp,Developer ID Application: Troupe Technology Limited (A86QBWJ43W)',
    '500,gopls,a.out,',
    '500,gopls,gopls,',
    '500,gpg-agent,gpg-agent,',
    '500,ipcserver,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,ipcserver.old,,',
    '500,ko,a.out,',
    '500,kubectl,a.out,',
    '500,lua-language-server,lua-language-server,',
    '500,Magnet,com.crowdcafe.windowmagnet,Apple Mac OS Application Signing',
    '500,Mattermost Helper,Mattermost.Desktop.helper,Apple Mac OS Application Signing',
    '500,Mattermost Helper (Renderer),Mattermost.Desktop.helper.Renderer,Apple Mac OS Application Signing',
    '500,PrinterProxy,com.apple.print.PrinterProxy,',
    '500,registry-redirect,a.out,',
    '500,rust-analyzer,rust_analyzer-d11ae4e1bae4360d,',
    '500,scdaemon,scdaemon,',
    '500,sdaudioswitch,sdaudioswitch,',
    '500,sdzoomplugin,,',
    '500,Slack,com.tinyspeck.slackmacgap,Apple Mac OS Application Signing',
    '500,Slack Helper,com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,Slack Helper (GPU),com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,Slack Helper (Renderer),com.tinyspeck.slackmacgap.helper,Apple Mac OS Application Signing',
    '500,syncthing,syncthing,',
    '500,terraform-provider-google-beta_v4.48.0_x5,a.out,',
    '500,terraform-provider-google_v4.48.0_x5,a.out,',
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
  -- TODO: Narrow this down
  AND NOT p.path LIKE '/opt/homebrew/Cellar/%'
  AND NOT p.path LIKE '/usr/local/Cellar/%/bin/%'
  AND NOT (
    p.path LIKE '/Users/%/homebrew/Cellar/%'
    AND p.name = 'limactl'
  )
  AND NOT (
    p.path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/com.elgato.cpu.sdPlugin/cpu'
    AND p.name = 'cpu'
  )
  AND NOT p.path IN ('/opt/socket_vmnet/bin/socket_vmnet')
GROUP BY
  pmm.pid