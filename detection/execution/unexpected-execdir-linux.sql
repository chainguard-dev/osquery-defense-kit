-- Programs running out of unexpected directories, such as /tmp (state-based)
--
-- references:
--   * https://blog.talosintelligence.com/2022/10/alchimist-offensive-framework.html
--
-- tags: transient process rapid state
-- platform: linux
SELECT
  p.pid,
  p.name,
  p.path,
  p.euid,
  p.gid,
  f.ctime,
  f.directory AS dirname,
  p.cmdline,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON hash.path = p.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  -- NOTE: Everything after this is shared with process_events/unexpected-executable-directory-events
WHERE
  dirname NOT IN (
    '/bin',
    '/usr/share/teams/resources/app.asar.unpacked/node_modules/slimcore/bin',
    '/sbin',
    '/usr/bin',
    '/usr/lib',
    '/usr/lib/bluetooth',
    '/usr/lib/cups/notifier',
    '/usr/share/teams',
    '/usr/lib/evolution-data-server',
    '/usr/lib/firefox',
    '/usr/lib/fwupd',
    '/usr/lib/ibus',
    '/usr/lib/libreoffice/program',
    '/usr/lib/polkit-1',
    '/usr/lib/slack',
    '/usr/lib/snapd',
    '/usr/lib/systemd',
    '/usr/lib/telepathy',
    '/usr/lib/udisks2',
    '/usr/lib/xorg',
    '/usr/lib64/firefox',
    '/usr/libexec',
    '/usr/sbin',
    '/usr/share/code'
  )
  AND dirname NOT LIKE '/home/%'
  AND dirname NOT LIKE '/nix/store/%'
  AND dirname NOT LIKE '/opt/%'
  AND dirname NOT LIKE '/snap/%'
  AND dirname NOT LIKE '/tmp/%/bin'
  AND dirname NOT LIKE '/tmp/go-build%'
  AND dirname NOT LIKE '/usr/lib/%'
  AND dirname NOT LIKE '/usr/lib64/%'
  AND dirname NOT LIKE '/usr/libexec/%'
  AND dirname NOT LIKE '/usr/local/%'
  AND p.path NOT IN (
    '/usr/lib/firefox/firefox',
    '/usr/lib64/firefox/firefox'
  )
  AND NOT (
    dirname = ''
    AND p.name LIKE 'runc%'
  )
