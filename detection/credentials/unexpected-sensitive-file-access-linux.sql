-- Unexpected programs accessing sensitive data stores (state-based)
--
-- This query is unfortunately of limited use, as the query is slow (250ms)
-- and it requires catching a program at the exact moment it has
-- the file open. An event-based version is advised.
--
-- references:
--   * https://attack.mitre.org/techniques/T1555/ (Credentials from Password Stores)
--
-- tags: transient often state file access
SELECT
  pof.pid,
  pof.fd,
  pof.path,
  f.uid AS file_uid,
  p.cwd AS cwd,
  p.euid,
  p.uid AS process_uid,
  p.name AS program_name,
  p.cmdline AS cmdline,
  pp.name AS parent_name,
  pp.cwd AS parent_cwd,
  pp.path AS parent_path,
  hp.sha256 AS parent_sha256,
  pf.filename AS program_base,
  hash.sha256,
  REPLACE(f.directory, u.directory, '~') AS dir,
  CONCAT (
    pf.filename,
    ',',
    p.name,
    ',',
    IIF(
      REGEX_MATCH (
        REPLACE(f.directory, u.directory, '~'),
        '([/~].*?/.*?/.*?)/',
        1
      ) != '',
      REGEX_MATCH (
        REPLACE(f.directory, u.directory, '~'),
        '([/~].*?/.*?/.*?)/',
        1
      ),
      REPLACE(f.directory, u.directory, '~')
    )
  ) AS exception_key
FROM
  process_open_files pof
  LEFT JOIN processes p ON pof.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file f ON pof.path = f.path
  LEFT JOIN file pf ON p.path = pf.path
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash hp ON pp.path = hp.path
WHERE
  f.uid != ''
  AND pf.filename != ''
  AND (
    pof.path IN ('/var/run/docker.sock')
    OR pof.path LIKE '/home/%/.ssh/%'
    OR pof.path LIKE '/home/%/.mozilla/firefox/%'
    OR pof.path LIKE '/home/%/.config/google-chrome/%'
    OR pof.path LIKE '/root/.ssh/%'
    OR pof.path LIKE '/root/.bash_history'
    OR pof.path LIKE '/home/%/.config/gcloud/%'
    OR pof.path LIKE '/home/%/.config/Slack/%'
    OR pof.path LIKE '/home/%/.bash_history'
    OR pof.path LIKE '/home/%/.cache/mozilla/firefox%'
    OR pof.path LIKE '/home/%/.config/mozilla/firefox%'
    OR pof.path LIKE '/home/%/.aws%'
  )
  AND NOT (
    file_uid == process_uid
    AND exception_key IN (
      'aws,aws,~/.aws',
      'python3,python3,~/.config/gcloud',
      'chrome_crashpad_handler,chrome_crashpad,',
      'chrome_crashpad_handler,chrome_crashpad,~/.config/google-chrome',
      'chrome,chrome,~/.config/google-chrome',
      'firefox,.firefox-wrappe,~/.cache/mozilla',
      'firefox,Web Content,~/.mozilla/firefox',
      'firefox,.firefox-wrappe,~/.mozilla/firefox',
      'firefox,file:// Content,~/.mozilla/firefox',
      'firefox,firefox,~/.cache/mozilla',
      'firefox,firefox,~/.mozilla/firefox',
      'firefox,file:// Content,~/.cache/mozilla',
      'firefox,firefox,~/snap/firefox',
      'firefox,Isolated Servic,~/.cache/mozilla',
      'firefox,Isolated Servic,~/snap/firefox',
      'firefox,Isolated Web Co,~/.cache/mozilla',
      'firefox,Isolated Web Co,~/.mozilla/firefox',
      'firefox,Isolated Web Co,~/snap/firefox',
      'firefox,Privileged Cont,~/.cache/mozilla',
      'firefox,Privileged Cont,~/.mozilla/firefox',
      'firefox,Privileged Cont,~/snap/firefox',
      'firefox,Web Content,~/.cache/mozilla',
      'firefox,Web Content,~/snap/firefox',
      'firefox,WebExtensions,~/.cache/mozilla',
      'firefox,WebExtensions,~/.mozilla/firefox',
      'firefox,WebExtensions,~/snap/firefox',
      'plugin-container,MainThread,~/.mozilla/firefox',
      'slack,slack,~/.config/Slack',
      'slack,slack,~/snap/slack'
    )
  )
GROUP BY
  pof.pid,
  pof.path
