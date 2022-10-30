-- Unusually small programs (state-based)
--
-- references:
--   * https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux
--
-- tags: transient process state
SELECT
  p.pid,
  p.path,
  p.cmdline,
  file.size,
  file.mode,
  file.type,
  p.cwd,
  p.euid,
  p.parent,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  file.size > 0
  AND file.size < 10000
  AND NOT file.path LIKE '/Users/%/.zsh/completion'
  AND NOT file.path LIKE '/home/%/.zsh/completion'
  AND NOT file.path LIKE '/home/%/.local/share/Steam/ubuntu%'
  AND NOT file.path LIKE '/home/%/.local/share/Steam/steamapps/%'
