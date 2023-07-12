-- Find unexpected programs with open lock files
--
-- false positives:
--   * many possible
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent filesystem state
-- platform: posix
SELECT
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    COALESCE(REGEX_MATCH (p0.path, '.*/(.*)', 1), p0.path),
    ',',
    COALESCE(
      REGEX_MATCH (REPLACE(pof.path, u.directory, '~'), '(.*)/.*', 1),
      REPLACE(pof.path, u.directory, '~')
    )
  ) AS exception_key,
  pof.path AS lock,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.start_time AS p0_start,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.start_time AS p1_start,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.start_time AS p2_start,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  JOIN users u ON p0.euid = u.uid
  LEFT JOIN process_open_files pof ON p0.pid = pof.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  pof.path LIKE "%.lock"
  AND NOT pof.path NOT LIKE "/run/user/%/%.lock"
  AND NOT p0.path LIKE '/System/%'
  AND NOT exception_key IN (
    '0,com.apple.MobileSoftwareUpdate.CryptegraftService,/private/var/db/softwareupdate/SplunkHistory',
    '0,snapd,/var/lib/snapd',
    '120,gnome-shell,/run/user/120',
    '200,NRDUpdated,/private~/SplunkHistory',
    '200,softwareupdated,/private~/SplunkHistory',
    '500,Adobe Premiere Pro 2023,~/Library/Caches/Adobe/Premiere Pro/23.0/SentryIO-db',
    '500,Beeper,~/Library/Application Support/Beeper/EventStore',
    '500,bridge-gui,~/Library/Application Support/protonmail/bridge-v3/sentry_cache',
    '500,bridge-gui,~/Library/Caches/protonmail/bridge-v3',
    '500,bridge,~/Library/Application Support/protonmail/bridge-v3/sentry_cache',
    '500,bridge,~/Library/Caches/protonmail/bridge-v3',
    '500,buildkitd,~/.local/share/buildkit',
    '500,Clipy,~/Library/Application Support/com.clipy-app.Clipy',
    '500,com.docker.backend,~/Library/Containers/com.docker.docker',
    '500,com.docker.build,~/.docker/desktop-build',
    '500,Craft,~/Library/Containers/com.lukilabs.lukiapp/Data/Library/Application Support/com.lukilabs.lukiapp',
    '500,Ecamm Live Stream Deck Plugin,~/Library/Application Support/com.elgato.StreamDeck/Sentry',
    '500,flyctl,~/.fly',
    '500,Hyprland,/run/user/1000',
    '127,pipewire,/run/user/127',
    '500,gnome-shell,/run/user/1000',
    '120,pipewire,/run/user/120',
    '500,iMovie,~/Movies/iMovie Library.imovielibrary',
    '500,Opera,~/Library/Application Support/com.operasoftware.Opera',
    '500,photolibraryd,~/Library/Photos/Libraries/Syndication.photoslibrary/database',
    '500,photolibraryd,~/Pictures/Photos Library.photoslibrary/database',
    '500,pipewire,/run/user/1000',
    '500,reMarkable,~/Library/Application Support/remarkable/desktop',
    '500,Stream Deck,~/Library/Application Support/com.elgato.StreamDeck/Sentry',
    '500,TwitchStudioStreamDeck,~/Library/Application Support/com.elgato.StreamDeck/Sentry'
  )
  AND NOT exception_key LIKE '500,com.apple.Virtualization.VirtualMachine,~/%'
  AND NOT exception_key LIKE '500,iMovie,%.imovielibrary'
  AND NOT exception_key LIKE '500,go,~/go/pkg/mod/cache/download/%'
  AND NOT exception_key LIKE '500,remindd,/private/var/folders/%/T/.AddressBookLocks'
  AND NOT exception_key LIKE '500,com.apple.Virtualization.VirtualMachine,/private/var/folders/%'
  AND NOT exception_key LIKE '500,lua-language-server,~/%'
  AND NOT exception_key LIKE '500,ykman-gui,/private/var/folders/%/T'
  AND NOT exception_key LIKE '500,golangci-lint,/private/var/folders/%/T'
  AND NOT exception_key LIKE '0,prl_disp_service,/Users/%/Parallels/%.pvm'
  AND NOT exception_key LIKE '500,iTermServer-%,~/Library/Application Support/iTerm2'
  AND NOT exception_key LIKE '500,%,/private/var/folders/%/T/Sentry_StreamDeck'
  AND NOT exception_key LIKE '500,gnome-software,/var/tmp/flatpak-cache-%'
  AND NOT exception_key LIKE '500,com.docker.backend,/private/var/folders/%/go/pkg/mod/cache/%'
GROUP BY
  p0.path,
  pof.path
