-- Unexpected programs accessing sensitive data stores (state-based)
--
-- This query is unfortunately of limited use, as the query is slow (250ms)
-- and it requires catching a program at the exact moment it has
-- the file open. An event-based version is advised.
--
-- references:
--   * https://attack.mitre.org/techniques/T1555/ (Credentials from Password Stores)
--
-- tags: transient state file access
SELECT
  pof.pid,
  pof.fd,
  pof.path,
  f.uid AS file_uid,
  p.cwd AS cwd,
  p.euid,
  p.start_time,
  p.uid AS process_uid,
  p.name AS program_name,
  p.cmdline AS cmdline,
  pp.name AS parent_name,
  pp.cwd AS parent_cwd,
  pp.path AS parent_path,
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
  -- Starting with processes is just slightly faster than starting with pof
  processes p
  LEFT JOIN process_open_files pof ON p.pid = pof.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file f ON pof.path = f.path
  LEFT JOIN file pf ON p.path = pf.path
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash hp ON pp.path = hp.path
WHERE
  -- minor optimization: filtering out low parents saves us another 5% of runtime
  p.parent > 2
  -- Large files are probably not secrets
  AND pf.filename != ''
  AND f.size < 1000000
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
  AND NOT p.cmdline LIKE 'less %id_rsa.pub'
  AND NOT (
    file_uid == process_uid
    AND exception_key IN (
      'aws,aws,~/.aws',
      'chrome,chrome,~/.config/google-chrome',
      'chrome_crashpad_handler,chrome_crashpad,',
      'firefox,Privileged Mozi,~/.mozilla/firefox',
      'chrome_crashpad_handler,chrome_crashpad,~/.config/google-chrome',
      'firefox,file:// Content,~/.cache/mozilla',
      'firefox,file:// Content,~/.mozilla/firefox',
      'firefox,file:// Content,~/snap/firefox',
      'firefox,firefox,~/.cache/mozilla',
      'firefox,firefox,~/.mozilla/firefox',
      'firefox,firefox,~/snap/firefox',
      'firefox,.firefox-wrappe,~/.cache/mozilla',
      'firefox,Sandbox Forked,~/snap/firefox',
      'firefox,.firefox-wrappe,~/.mozilla/firefox',
      'firefox,Isolated Servic,~/.cache/mozilla',
      'firefox,Isolated Servic,~/.mozilla/firefox',
      'firefox,Isolated Servic,~/snap/firefox',
      'firefox,Isolated Web Co,~/.cache/mozilla',
      'firefox,Isolated Web Co,~/.mozilla/firefox',
      'firefox,Isolated Web Co,~/snap/firefox',
      'firefox,Privileged Cont,~/.cache/mozilla',
      'firefox,Privileged Cont,~/.mozilla/firefox',
      'firefox,Privileged Cont,~/snap/firefox',
      'firefox,Web Content,~/.cache/mozilla',
      'firefox,Web Content,~/.mozilla/firefox',
      'firefox,Web Content,~/snap/firefox',
      'firefox,WebExtensions,~/.cache/mozilla',
      'firefox,WebExtensions,~/.mozilla/firefox',
      'firefox,WebExtensions,~/snap/firefox',
      'plugin-container,MainThread,~/.mozilla/firefox',
      'plugin-container,MainThread,~/snap/firefox',
      'python3.10,python3,~/.config/gcloud',
      'python3.11,python3,~/.config/gcloud',
      'python3.12,python3,~/.config/gcloud',
      'python3,python3,~/.config/gcloud',
      'slack,slack,~/.config/Slack',
      'slack,slack,~/snap/slack',
      'soffice.bin,soffice.bin,~/.mozilla/firefox',
      'vim,vim,~/.aws'
    )
  )
GROUP BY
  pof.pid,
  pof.path
