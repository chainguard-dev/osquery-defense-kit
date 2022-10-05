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
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  hash.sha256,
  REPLACE(p.cwd, u.directory, "~") AS dir,
  CONCAT(
    p.name,
    ",",
    IIF(
      REGEX_MATCH(
        REPLACE(p.cwd, u.directory, "~"),
        "([/~].*?/.*?/.*?)/",
        1
      ) != "",
      REGEX_MATCH(
        REPLACE(p.cwd, u.directory, "~"),
        "([/~].*?/.*?/.*?)/",
        1
      ),
      REPLACE(p.cwd, u.directory, "~")
    )
  ) AS exception_key
FROM processes p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN hash ON p.path = hash.path
WHERE p.cwd LIKE "%/.%"
  AND NOT exception_key IN ("bash,~/go/src", "mysqld,~/.local/share")
  OR program_name IN ("bindfs")
  OR dir LIKE "~/go/src/%"
  OR dir LIKE "~/src/%"
  OR dir LIKE "~/%/.github%"
