-- Unexpected socket events
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net
-- interval: 601
-- platform: posix
SELECT
    s.status,
    s.family,
    s.fd,
    s.remote_address,
    s.remote_port,
    s.local_port,
    COALESCE(REGEX_MATCH (s.path, '.*/(.*)', 1), s.path) AS basename,
    REPLACE(f.directory, u.directory, '~') AS homedir,
    CONCAT(
        MIN(s.auid, 500),
        ",",
        MIN(f.uid, 500),
        ",",
        MIN(s.remote_port, 32768),
        ",",
        COALESCE(REGEX_MATCH (s.path, '.*/(.*)', 1), s.path)
    ) as exception_key,
    RTRIM(
        COALESCE(
            REGEX_MATCH (
                REPLACE(f.directory, u.directory, '~'),
                '([/~].*?/.*?)/',
                1
            ),
            f.directory
        ),
        "/"
    ) AS top2_dir,
    -- Child
    s.path AS p0_path,
    s.pid AS p0_pid,
    s.auid AS p0_euid,
    TRIM(COALESCE(p.cmdline, pe.cmdline)) AS p0_cmd,
    TRIM(COALESCE(p.cwd, pe.cwd)) AS p0_cwd,
    hash.sha256 AS p0_sha256,
    -- Parent
    COALESCE(p.parent, pe.parent) AS p1_pid
FROM
    socket_events AS s
    LEFT JOIN process_events pe ON s.pid = pe.pid
    AND pe.time > (strftime('%s', 'now') -660)
    LEFT JOIN processes p ON s.pid = p.pid
    LEFT JOIN file f ON s.path = f.path
    LEFT JOIN users u ON f.uid = u.uid
    LEFT JOIN hash ON s.path = hash.path
WHERE
    s.time > (strftime('%s', 'now') -600)
    AND s.action = "connect"
    AND s.remote_port > 0
    AND s.remote_address NOT IN (
        '127.0.0.1',
        '::ffff:127.0.0.1',
        '::1',
        '::',
        '0.0.0.0'
    )
    AND s.remote_address NOT LIKE 'fe80:%'
    AND s.remote_address NOT LIKE '127.%'
    AND s.remote_address NOT LIKE '192.168.%'
    AND s.remote_address NOT LIKE '100.7%'
    AND s.remote_address NOT LIKE '172.1%'
    AND s.remote_address NOT LIKE '172.2%'
    AND s.remote_address NOT LIKE '172.30.%'
    AND s.remote_address NOT LIKE '172.31.%'
    AND s.remote_address NOT LIKE '::ffff:172.%'
    AND s.remote_address NOT LIKE '10.%'
    AND s.remote_address NOT LIKE '::ffff:10.%'
    AND s.remote_address NOT LIKE '::ffff:192.168.%'
    AND s.remote_address NOT LIKE 'fc00:%'
    AND NOT s.path LIKE '/Applications/%' -- NOTE: Do not filter out /bin (bash) or /usr/bin (nc)
    AND NOT top2_dir IN (
        '/Library/Apple',
        '/Library/Application Support',
        '/Library/Kandji',
        '/System/Volumes',
        '~/bin',
        '/usr/local',
        '/opt/homebrew',
        '~/Apps',
        '~/code',
        '~/work',
        '~/github',
        '~/src',
        '~/go',
        '~/Applications',
        '/System/Applications',
        '/System/Library',
        '/usr/libexec',
        '/usr/sbin'
    )
    AND NOT exception_key IN (
        '500,0,123,sntp',
        '500,0,22,ssh',
        '500,0,443,velociraptor',
        '500,0,32768,ksfetch',
        '500,500,32768,ksfetch',
        '500,500,443,old',
        '500,0,32768,syncthing',
        '500,0,443,chrome',
        '500,0,443,curl',
        '500,0,443,git-remote-http',
        '500,0,443,ksfetch',
        '500,0,443,launcher',
        '500,0,443,slack',
        '500,0,31488,sntp',
        '500,500,443,go',
        '500,0,443,syncthing',
        '500,0,443,wget',
        '500,0,5228,chrome',
        '500,0,53,chrome',
        '500,0,53,git',
        '500,0,443,firefox',
        '500,0,80,firefox',
        '500,0,443,node',
        '500,500,2304,cloud_sql_proxy',
        '500,500,443,cloud_sql_proxy',
        '500,500,80,cloud_sql_proxy',
        '500,0,53,launcher',
        '500,0,53,NetworkManager',
        '500,0,53,slack',
        '500,0,53,wget',
        '500,0,80,chrome',
        '500,0,9,launcher',
        '500,500,13568,Code Helper',
        '500,500,22,ssh',
        '500,500,32768,cloud-sql-proxy',
        '500,500,4318,Code Helper (Plugin)',
        '500,500,443,Code Helper (Plugin)',
        '500,500,443,Code Helper',
        '500,500,443,copilot-agent-macos-arm64',
        '500,500,443,Electron',
        '500,500,443,gitsign',
        '500,500,443,ksfetch',
        '500,500,443,node',
        '500,500,443,wolfictl',
        '500,500,80,copilot-agent-macos-arm64',
        '500,500,80,node'
    )
    AND NOT (
        basename = "Python"
        AND (
            p0_cmd LIKE '%/gcloud.py%'
            OR p0_cmd LIKE '%/google-cloud-sdk/%'
            OR p0_cmd LIKE '%pip install%'
            OR p0_cmd LIKE '%googlecloudsdk/%'
            OR p0_cmd LIKE '%/bin/aws%'
            OR p0_cmd LIKE "%/gsutil/%"
        )
    )
GROUP BY
    s.pid,
    exception_key