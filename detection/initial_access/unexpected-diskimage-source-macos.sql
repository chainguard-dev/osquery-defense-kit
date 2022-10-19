-- Surface ISO/DMG disk images that were downloaded from unexpected places
--
-- references:
--   * https://attack.mitre.org/techniques/T1566/001/ (Phishing: Spearphishing Attachment)
--   * https://attack.mitre.org/techniques/T1204/002/ (User Execution: Malicious File)
--   * https://unit42.paloaltonetworks.com/chromeloader-malware/
--
-- false positives:
--   * disk images downloaded from a location not in the exception list
--
-- platform: darwin
-- tags: persistent filesystem spotlight
SELECT
  file.path,
  file.size,
  datetime(file.btime, 'unixepoch') AS file_created,
  magic.data,
  ea.value AS url,
  REGEX_MATCH (ea.value, '/[\w_-]+\.([\w\._-]+)[:/]', 1) AS domain,
  REGEX_MATCH (ea.value, '/([\w_-]+\.[\w\._-]+)[:/]', 1) AS host
FROM
  mdfind
  LEFT JOIN file ON mdfind.path = file.path
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    mdfind.query = "kMDItemWhereFroms != '' && kMDItemFSName == '*.iso'"
    OR mdfind.query = "kMDItemWhereFroms != '' && kMDItemFSName == '*.dmg'"
  )
  AND ea.key = 'where_from'
  AND file.btime > (strftime('%s', 'now') -86400)
  AND domain NOT IN (
    'adobe.com',
    'alfredapp.com',
    'android.com',
    'apple.com',
    'download.prss.microsoft.com',
    'arc.net',
    'balsamiq.com',
    'brave.com',
    'digidesign.com',
    'digidesign.com',
    'gaomon.net',
    'epson.com',
    'fcix.net',
    'xtom.com',
    'gaomon.net',
    'oracle.com',
    'akmedia.digidesign.com',
    'canon.co.uk',
    'cdn.mozilla.net',
    'charlesproxy.com',
    'csclub.uwaterloo.ca',
    'docker.com',
    'duckduckgo.com',
    'eclipse.org',
    'gimp.org',
    'github.io',
    'githubusercontent.com',
    'grammarly.com',
    'integodownload.com',
    'jetbrains.com',
    'libreoffice.org',
    'loom.com',
    'microsoft.com',
    'minecraft.net',
    'mirrorservice.org',
    'mojang.com',
    'mozilla.org',
    'mysql.com',
    'ocf.berkeley.edu',
    'oobesaas.adobe.com',
    'osuosl.org',
    'pqrs.org',
    'steampowered.com',
    'c-wss.com',
    'irccloud.com',
    'discordapp.net',
    'getutm.app',
    'dogado.de',
    'vc.logitech.com',
    'steampowered.com',
    'discord.com',
    'logitech.com',
    'skype.com',
    'remarkable.com',
    'balena.io',
    'signal.org',
    'prusa3d.com',
    'google.ca',
    'zsa.io',
    'slack-edge.com',
    'tableplus.com',
    'ubuntu.com',
    'umd.edu',
    'virtualbox.org',
    'warp.dev',
    'webex.com'
  )
  AND host NOT IN (
    'dl.google.com',
    'www.google.com',
    'warp-releases.storage.googleapis.com',
    'mail.google.com',
    'github.com',
    'ubuntu.com',
    'balsamiq.com',
    'tableplus.com',
    'discord.com',
    'dl.discordapp.net',
    'obsproject.com',
    'www.messenger.com',
    'brave.com',
    'emacsformacosx.com',
    'store.steampowered.com',
    'wavebox.io',
    'manual.canon',
    'dygma.com',
    'duckduckgo.com',
    'obsidian.md'
  )
  -- Yes, these are meant to be fairly broad.
  AND host NOT LIKE 'download%'
  AND host NOT LIKE 'cdn%'
  AND host NOT LIKE '%.edu'
  AND host NOT LIKE 'github-production-release-asset-%.s3.amazonaws.com'
  AND host NOT LIKE '%.org'
  AND host NOT LIKE 'dl.%'
  AND host NOT LIKE 'dl-%'
  AND host NOT LIKE 'mirror%'
  AND host NOT LIKE 'driver.%'
  AND host NOT LIKE 'support%'
  AND host NOT LIKE 'software%'
  AND host NOT LIKE 'www.google.%'
  AND host NOT LIKE '%release%.storage.googleapis.com'
  AND NOT (
    host LIKE '%.fbcdn.net'
    AND file.filename LIKE 'Messenger.%.dmg'
  )
GROUP BY
  ea.value
