-- Slow query to find root programs with an open socket and few shared libraries
--
-- false positives:
--   * some minimalist daemons
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent process state seldom
-- platform: macos
SELECT
  p.uid,
  p.euid,
  pos.protocol,
  pos.pid,
  pos.remote_address,
  pos.local_address,
  pos.local_port,
  pos.remote_port,
  p.name,
  p.start_time,
  p.parent,
  p.cgroup_path,
  p.path,
  pos.state,
  GROUP_CONCAT(DISTINCT pmm.path) AS libs,
  COUNT(DISTINCT pmm.path) AS lib_count,
  CONCAT (
    MIN(p.euid, 500),
    ',',
    p.name,
    ',',
    REPLACE(p.path, u.directory, '~'),
    s.authority
  ) AS exception_key
FROM
  processes p
  JOIN process_memory_map pmm ON p.pid = pmm.pid
  JOIN process_open_sockets pos ON p.pid = pos.pid
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN users u ON f.uid = u.uid
  LEFT JOIN signature s ON p.path = s.path
WHERE
  p.pid IN (
    SELECT
      processes.pid
    FROM
      process_open_sockets
      JOIN processes ON process_open_sockets.pid = processes.pid
      AND family != 1 -- The outer query is slow due to the use of process_memory_map, so narrow down our choices here
    WHERE
      processes.path NOT LIKE '/Library/Apple/%'
      AND processes.path NOT LIKE '/Library/Elastic/Agent/data/%'
      AND processes.path NOT LIKE '/private/var/db/com.apple.xpc.roleaccountd.staging/%'
      AND processes.path NOT LIKE '/private/var/kolide-k2/k2device.kolide.com/updates/%.app/Contents/MacOS/%'
      AND processes.path NOT LIKE '/sbin/%'
      AND processes.path NOT LIKE '/System/%'
      AND processes.path NOT LIKE '/usr/bin/%'
      AND processes.path NOT LIKE '/usr/libexec/%'
      AND processes.path NOT LIKE '/usr/sbin/%'
      AND NOT (
        processes.euid >= 500
        AND (
          processes.path LIKE '/Applications/%.app/Contents/Frameworks/%/Contents/MacOS/%'
          OR processes.path LIKE '/Applications/%.app/Contents/MacOS/%'
          OR processes.path LIKE '/nix/store/%/bin/nix'
          OR processes.path LIKE '/opt/%/bin/%'
          OR processes.path LIKE '/private/var/folders/%/X/com.google.Chrome.code_sign_clone/code_sign_clone%'
          OR processes.path LIKE '/Users/%/Applications/zoom.us.app/Contents/MacOS/zoom.us'
          OR processes.path LIKE '/Users/%/go/bin/%'
          OR processes.path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/%'
          OR processes.path LIKE '/Users/%/Library/Application Support/Figma/FigmaAgent.app/Contents/MacOS/figma_agent'
          OR processes.path LIKE '/Users/%/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/%'
          OR processes.path IN (
            '/Applications/AirBuddy.app/Contents/Library/LoginItems/AirBuddyHelper.app/Contents/XPCServices/MobileDevicesService.xpc/Contents/MacOS/MobileDevicesService',
            '/Applications/Elgato Stream Deck.app/Contents/Helpers/node20',
            '/Applications/GoLand.app/Contents/plugins/go-plugin/lib/dlv/macarm/dlv',
            '/Applications/Google Drive.app/Contents/Applications/FinderHelper.app/Contents/PlugIns/FinderSyncExtension.appex/Contents/MacOS/FinderSyncExtension',
            '/Applications/Google Drive.app/Contents/PlugIns/DFSFileProviderExtension.appex/Contents/MacOS/DFSFileProviderExtension',
            '/Applications/lghub.app/Contents/MacOS/lghub_updater.app/Contents/MacOS/lghub_updater',
            '/Applications/Loom.app/Contents/Resources/binaries/loom-recorder-production',
            '/Applications/Ollama.app/Contents/Resources/ollama',
            '/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/lima/bin/limactl.ventura',
            '/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/lima/bin/qemu-system-aarch64',
            '/Applications/Syncthing.app/Contents/Resources/syncthing/syncthing',
            '/Library/Application Support/Adobe/Adobe Desktop Common/ADS/Adobe Desktop Service.app/Contents/MacOS/Adobe Desktop Service',
            '/Library/Application Support/Adobe/Adobe Desktop Common/IPCBox/AdobeIPCBroker.app/Contents/MacOS/AdobeIPCBroker',
            '/Library/Application Support/Kandji/Kandji Menu/Kandji Menu.app/Contents/MacOS/Kandji Menu',
            '/Library/Application Support/Logitech.localized/LogiOptionsPlus/logioptionsplus_agent.app/Contents/Frameworks/logioptionsplus_updater.app/Contents/MacOS/logioptionsplus_updater',
            '/Library/Application Support/Logitech.localized/LogiOptionsPlus/logioptionsplus_agent.app/Contents/MacOS/logioptionsplus_agent',
            '/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver',
            '/Library/Frameworks/Python.framework/Versions/3.10/Resources/Python.app/Contents/MacOS/Python',
            '/Library/Kandji/Kandji Agent.app/Contents/Helpers/Kandji Daemon.app/Contents/MacOS/kandji-daemon',
            '/Library/Printers/Brother/Utilities/Server/NETserver.app/Contents/MacOS/NETserver',
            '/Library/Printers/Brother/Utilities/Server/USBAppControl.app/Contents/MacOS/USBAppControl',
            '/Library/Printers/Brother/Utilities/Server/WorkflowAppControl.app/Contents/MacOS/WorkflowAppControl',
            '/usr/local/bin/node',
            '/Volumes/Google Chrome/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Volumes/Slack/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper'
          )
        )
      ) -- uid0-499 exceptions
      AND NOT processes.path IN (
        '/Applications/Tailscale.app/Contents/PlugIns/IPNExtension.appex/Contents/MacOS/IPNExtension',
        '/Applications/WiFiman Desktop.app/Contents/service/wifiman-desktopd',
        '/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint',
        '/Library/Kandji/Kandji Agent.app/Contents/Helpers/Kandji Daemon.app/Contents/MacOS/kandji-daemon',
        '/Library/safeqclientcore/bin/safeqclientcore',
        '/usr/local/sbin/velociraptor'
      )
      AND processes.start_time < (strftime('%s', 'now') -600)
    GROUP BY
      processes.path
  )
  AND NOT exception_key = '500,Steam Helper,~/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/Frameworks/Steam Helper.app/Contents/MacOS/Steam HelperDeveloper ID Application: Valve Corporation (MXGJJ98X76)'
  AND NOT exception_key LIKE '500,python3.%,~/miniconda/envs/skilljar-api/bin/python3.%'
  AND pmm.path LIKE "%.dylib"
GROUP BY
  pos.pid
HAVING
  lib_count IN (1, 2)
  AND libs NOT LIKE '/Applications/%/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib,/usr/lib/libobjc-trampolines.dylib'
  AND libs NOT LIKE '/usr/lib/libobjc-trampolines.dylib,/Applications/%.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib'
