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
-- tags: persistent filesystem spotlight often
SELECT
  file.path,
  file.size,
  datetime(file.btime, 'unixepoch') AS file_created,
  magic.data,
  hash.sha256,
  signature.identifier,
  signature.authority,
  ea.value AS url,
  REGEX_MATCH (ea.value, '/[\w_-]+\.([\w\._-]+)[:/]', 1) AS domain,
  REGEX_MATCH (ea.value, '/([\w_-]+\.[\w\._-]+)[:/]', 1) AS host
FROM
  mdfind
  LEFT JOIN file ON mdfind.path = file.path
  LEFT JOIN hash ON mdfind.path = hash.path
  LEFT JOIN extended_attributes ea ON mdfind.path = ea.path
  LEFT JOIN magic ON mdfind.path = magic.path
  LEFT JOIN signature ON mdfind.path = signature.path
WHERE
  (
    mdfind.query = "kMDItemWhereFroms != '' && kMDItemFSName == '*.iso'"
    OR mdfind.query = "kMDItemWhereFroms != '' && kMDItemFSName == '*.dmg'"
    OR mdfind.query = "kMDItemWhereFroms != '' && kMDItemFSName == '*.pkg'"
  )
  AND ea.key = 'where_from'
  AND file.btime > (strftime('%s', 'now') -86400)
  AND domain NOT IN (
    'adobe.com',
    'akmedia.digidesign.com',
    'alfredapp.com',
    'amazon.com',
    'android.com',
    'ankiweb.net',
    'apple.com',
    'arc.net',
    'asana.com',
    'astutegraphics.com',
    'backblazeb2.com',
    'balena.io',
    'balsamiq.com',
    'bblmw.com',
    'bluestacks.com',
    'boxcdn.net',
    'box.com',
    'brave.com',
    'byfly.by',
    'canon.co.uk',
    'cdn.mozilla.net',
    'charlesproxy.com',
    'chatgpt.com',
    'cloudfront.net',
    'cron.com',
    'csclub.uwaterloo.ca',
    'curseforge.com',
    'c-wss.com',
    'descript.com',
    'desktop.evernote.com',
    'digidesign.com',
    'discordapp.net',
    'discord.com',
    'dl.meitu.com',
    'dl.sourceforge.net',
    'docker.com',
    'dogado.de',
    'download.prss.microsoft.com',
    'duckduckgo.com',
    'eclipse.org',
    'emeet.com',
    'epson.com',
    'eventideaudio.com',
    'fcix.net',
    'figma.com',
    'foundry.com',
    'gaomon.net',
    'getutm.app',
    'gimp.org',
    'github.io',
    'githubusercontent.com',
    'google.ca',
    'google.com',
    'grammarly.com',
    'imazing.com',
    'integodownload.com',
    'irccloud.com',
    'jetbrains.com',
    'kagi.com',
    'kolide.com',
    'libreoffice.org',
    'live.com',
    'logitech.com',
    'loom.com',
    'macbartender.com',
    'macroplant.com',
    'maxon.net',
    'microsoft.com',
    'minecraft.net',
    'mirrorservice.org',
    'mm.cfix.net',
    'mm.fcix.net',
    'mojang.com',
    'mozilla.org',
    'mutedeck.com',
    'mysql.com',
    'notion.so',
    'notion-static.com',
    'ocf.berkeley.edu',
    'odvdev.at',
    'office.com',
    'oobesaas.adobe.com',
    'openra.net',
    'oracle.com',
    'osuosl.org',
    'overwolf.com',
    'pathofexile.com',
    'perforce.com',
    'poecdn.com',
    'pqrs.org',
    'proxmox.com',
    'prusa3d.com',
    'raspberrypi.com',
    'redhat.com',
    'remarkable.com',
    'rewind.ai',
    's3.amazonaws.com',
    'securew2.com',
    'signal.org',
    'siliconmotion.com',
    'skype.com',
    'slack.com',
    'slack-edge.com',
    'stclairsoft.com',
    'steampowered.com',
    'synaptics.com',
    'tableplus.com',
    'teams.cdn.office.net',
    'techsmith.com',
    'tweaknews.eu',
    'ubuntu.com',
    'ultimaker.com',
    'umd.edu',
    'usa.canon.com',
    'uubyte.com',
    'vc.logitech.com',
    'vimcal.com',
    'virtualbox.org',
    'viture.dev',
    'vmware.com',
    'warp.dev',
    'webex.com',
    'whatsapp.com',
    'xtom.com',
    'gitbutler.com',
    'xx.fbcdn.net',
    'yubico.com',
    'zoo.dev',
    'zoomgov.com',
    'zoom.us',
    'zsa.io'
  )
  -- NOTE: Do not put all of storage.googleapis.com or similarly generic hosts here
  AND host NOT IN (
    'adoptium.net',
    'arc.net',
    'asana.com',
    'awscli.amazonaws.com',
    'balsamiq.com',
    'bearly.ai',
    'blyt.net',
    'brave.com',
    'calibre-ebook.com',
    'chatgpt.com',
    'cron.com',
    'discord.com',
    'dl.discordapp.net',
    'dl2.discordapp.net',
    'dl.google.com',
    'duckduckgo.com',
    'dygma.com',
    'emacsformacosx.com',
    'epson.com',
    'evernote.com',
    'multipass.run',
    'fbcdn.net',
    'figma.com',
    'flipperzero.one',
    'fnord.com',
    'getkap.co',
    'github.com',
    'gitbutler.com',
    'go.dev',
    'imazing.com',
    'kittycad.io',
    'krisp.ai',
    'macroplant.com',
    'mail.google.com',
    'mangoslab.blob.core.windows.net',
    'manual.canon',
    'manytricks.com',
    'maxon.net',
    'mimestream.com',
    'mnvoip.mm.fcix.net',
    'mutedeck.com',
    'obdev.at',
    'obsidian.md',
    'obsproject.com',
    'opalcamera.com',
    'openai.com',
    'persistent.oaistatic.com',
    'portswigger-cdn.net',
    'posit.co',
    'presenting.app',
    'proton.me',
    'rancherdesktop.io',
    'rectangleapp.com',
    's3.amazonaws.com',
    'scribehow.com',
    'shottr.cc',
    'sipapp.fra1.digitaloceanspaces.com',
    'sipapp.io',
    'sourceforge.net',
    'sourcegraph.com',
    'stclairsoft.s3.amazonaws.com',
    'store.steampowered.com',
    'superkey.app',
    'superhuman.com',
    'tableplus.com',
    'textexpander.com',
    'tosmediaserver.schwab.com',
    'transmissionbt.com',
    'ubuntu.com',
    'ultimaker.com',
    'universal-blue.discourse.group',
    'warp-releases.storage.googleapis.com',
    'wavebox.io',
    'www.google.com',
    'www.messenger.com',
    'zed.dev',
    'zoo.dev',
    'zoom.us'
  )
  -- Yes, these are meant to be fairly broad.
  AND host NOT LIKE 'download%'
  AND host NOT LIKE 'cdn%'
  AND host NOT LIKE '%.cdn.%.com'
  AND host NOT LIKE '%.edu'
  AND host NOT LIKE 'github-production-release-asset-%.s3.amazonaws.com'
  AND host NOT LIKE '%.org'
  AND host NOT LIKE 'dl.%'
  AND host NOT LIKE 'dl-%'
  AND host NOT LIKE 'mirror%'
  AND host NOT LIKE 'driver.%'
  AND host NOT LIKE 'support%'
  AND host NOT LIKE 's3.%.amazonaws.com'
  AND host NOT LIKe '%.s3.%.amazonaws.com'
  AND host NOT LIKE 'software%'
  AND host NOT LIKE 'www.google.%'
  AND host NOT LIKE '%release%.storage.googleapis.com'
  AND ea.value NOT LIKE 'https://storage.googleapis.com/copilot-mac-releases/%'
  AND ea.value NOT LIKE 'https://storage.googleapis.com/kolide-k2-production-downloads-f414/%'
GROUP BY
  ea.value
