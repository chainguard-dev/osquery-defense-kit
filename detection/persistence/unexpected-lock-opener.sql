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
    CONCAT(
        MIN(p0.euid, 500),
        ',',
        COALESCE(REGEX_MATCH (p0.path, '.*/(.*)', 1), p0.path),
        ',',
        REGEX_MATCH (
            REPLACE(pof.path, u.directory, '~'),
            '(.*)/.*',
            1
        )
    ) AS exception_key,
    pof.path AS lock,
    -- Child
    p0.pid AS p0_pid,
    p0.path AS p0_path,
    p0.name AS p0_name,
    p0.cmdline AS p0_cmd,
    p0.cwd AS p0_cwd,
    p0.cgroup_path AS p0_cgroup,
    p0.euid AS p0_euid,
    p0_hash.sha256 AS p0_sha256
FROM processes p0
    JOIN users u ON p0.euid = u.uid
    LEFT JOIN process_open_files pof ON p0.pid = pof.pid
    LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
    LEFT JOIN processes p1 ON p0.parent = p1.pid
    LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
    LEFT JOIN processes p2 ON p1.parent = p2.pid
    LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE pof.path LIKE "%.lock"
    AND pof.path NOT LIKE "/run/user/1%/%.lock"
    AND NOT exception_key IN (
        '0,com.apple.MobileSoftwareUpdate.CryptegraftService,/private/var/db/softwareupdate/SplunkHistory',
        '0,snapd,/var/lib/snapd',
        '200,softwareupdated,/private~/SplunkHistory',
        '500,Beeper,~/Library/Application Support/Beeper/EventStore',
        '500,bridge-gui,~/Library/Application Support/protonmail/bridge-v3/sentry_cache',
        '500,bridge-gui,~/Library/Caches/protonmail/bridge-v3',
        '500,bridge,~/Library/Application Support/protonmail/bridge-v3/sentry_cache',
        '500,bridge,~/Library/Caches/protonmail/bridge-v3',
        '500,buildkitd,~/.local/share/buildkit',
        '500,com.docker.backend,~/Library/Containers/com.docker.docker',
        '500,photolibraryd,~/Library/Photos/Libraries/Syndication.photoslibrary/database',
        '500,photolibraryd,~/Pictures/Photos Library.photoslibrary/database'
    )
    AND NOT exception_key LIKE '500,com.apple.Virtualization.VirtualMachine,~/%'
    AND NOT exception_key LIKE '500,com.apple.Virtualization.VirtualMachine,/private/var/folders/%'
    AND NOT exception_key LIKE '500,lua-language-server,~/%'
    AND NOT exception_key LIKE '500,iTermServer-%,~/Library/Application Support/iTerm2'
    AND NOT exception_key LIKE '500,%,/private/var/folders/%/T/Sentry_StreamDeck'
GROUP BY p0.path,
    pof.path