SELECT p.pid,
    p.path,
    p.name,
    p.cmdline,
    p.cwd,
    p.euid,
    p.parent,
    pp.path AS parent_path,
    pp.name AS parent_name,
    pp.cmdline AS parent_cmdline,
    pp.euid AS parent_euid
FROM processes p
    JOIN processes pp ON p.parent = pp.pid
WHERE
p.cwd LIKE "%/.%" AND NOT (
    p.cwd LIKE "%/.local/share%" OR
    p.cwd LIKE "%/.vscode/extensions%" OR
    p.cwd LIKE "/Users/%/.%" OR
    p.cwd LIKE "/home/%/.%" OR
    p.cwd LIKE "/Library/Apple/System/Library/InstallerSandboxes/.PKInstallSandboxManager-SystemSoftware/%" OR
    p.name = 'bindfs' OR
    p.path="/usr/libexec/dirhelper"
)
