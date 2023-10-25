-- Programs running with a hidden current working directory (event-based)
--
-- false positives:
--   * Users rummaging through their configuration files
--
-- NOTES:
--   * Disabled on macOS, as the cwd field as NULL there
--
-- references:
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- tags: transient
-- platform: linux
-- interval: 600
SELECT
    COALESCE(REGEX_MATCH(TRIM(pe.cwd, '"'), "/(\..*?)\/", 1), REGEX_MATCH(TRIM(pe.cwd, '"'), "/(\..*)", 1)) AS hidden_base,
    REGEX_MATCH(TRIM(pe.cwd, '"'), "/(\..*)", 1) AS hidden_part,
    COALESCE(REGEX_MATCH (TRIM(pe.cwd, '"'), '.*/(.*)', 1), pe.cwd) AS basename,
    CONCAT (
        COALESCE(REGEX_MATCH (TRIM(pe.path, '"'), '.*/(.*)', 1), pe.path),
        ',',
        REGEX_MATCH(TRIM(pe.cwd, '"'), "/(\..*?)\/", 1), REGEX_MATCH(TRIM(pe.cwd, '"'), "/(\..*)", 1)
    ) AS exception_key,
    -- Child
    pe.path AS p0_path,
    COALESCE(REGEX_MATCH (pe.path, '.*/(.*)', 1), pe.path) AS p0_name,
    TRIM(pe.cmdline) AS p0_cmd,
    TRIM(pe.cwd, '"') AS p0_cwd,
    pe.status AS p0_status,
    pe.time AS p0_time,
    pe.pid AS p0_pid,
    pe.euid AS p0_euid,
    -- Parent
    pe.parent AS p1_pid,
    TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
    p1.cwd AS p1_cwd,
    COALESCE(p1.path, pe1.path) AS p1_path,
    COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
    REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name
FROM
    process_events pe
    LEFT JOIN users u ON pe.uid = u.uid
    LEFT JOIN processes p ON pe.pid = p.pid -- Parents (via two paths)
    LEFT JOIN processes p1 ON pe.parent = p1.pid
    LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
    LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
    AND pe1.time > (strftime('%s', 'now') -60660)
    AND pe1.cmdline != ''
    LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
WHERE
    pe.time > (strftime('%s', 'now') -60600)
    AND pe.cwd LIKE '%/.%'
    AND NOT (
        hidden_base IN (
            '.cache',
            '.cargo',
            '.gradle',
            '.kotlin',
            '.npm',
            '.git',
            '.gimme',
            '.vscode',
            '.vim',
            '.config',
            '.github',
            '.provisio',
            '.terraform.d',
            '.emacs.d',
            '.gmailctl',
            '.oh-my-zsh',
            '.zsh'
        )
        OR exception_key LIKE '%sh,~/.Trash'
    )
    AND NOT pe.cwd LIKE '%/build/%'
    AND NOT pe.cwd LIKE '%/out/%'
GROUP BY
    p.cmdline,
    p.cwd;