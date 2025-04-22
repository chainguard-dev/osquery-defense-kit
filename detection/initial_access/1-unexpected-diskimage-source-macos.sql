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
  REGEX_MATCH (ea.value, '/([\w_-]+\.[\w\._-]+)[:/]', 1) AS host,
  COALESCE(
    REGEX_MATCH (
      ea.value,
      '/\/[\w_-]+\.([\w_-]+\.[\w\._-]+)[:/]',
      1
    ),
    -- Fallback to hostname if no subdomain is found
    REGEX_MATCH (ea.value, '/([\w_-]+\.[\w\._-]+)[:/]', 1)
  ) AS subdomain
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
  AND subdomain NOT IN (
    'adguard.com',
    'adobe.com',
    'akmedia.digidesign.com',
    'alfredapp.com',
    'amazon.com',
    'android.com',
    'ankerwork.com',
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
    'box.com',
    'boxcdn.net',
    'brave.com',
    'byfly.by',
    'claude.ai',
    'c-wss.com',
    'canon.co.uk',
    'cdn.mozilla.net',
    'charlesproxy.com',
    'chatgpt.com',
    'chime.aws',
    'cloudfront.net',
    'cron.com',
    'csclub.uwaterloo.ca',
    'curseforge.com',
    'descript.com',
    'desktop.evernote.com',
    'digidesign.com',
    'discord.com',
    'discordapp.net',
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
    'expensify.com',
    'fcix.net',
    'figma.com',
    'foundry.com',
    'gaomon.net',
    'getutm.app',
    'gimp.org',
    'gitbutler.com',
    'github.io',
    'githubusercontent.com',
    'google.ca',
    'google.com',
    'grammarly.com',
    'granola.ai',
    'imazing.com',
    'integodownload.com',
    'irccloud.com',
    'jetbrains.com',
    'kagi.com',
    'kolide.com',
    'libreoffice.org',
    'live.com',
    'lmstudio.ai',
    'logitech.com',
    'loom.com',
    'macbartender.com',
    'macroplant.com',
    'maxon.net',
    'microsoft.com',
    'minecraft.net',
    'mirrors.serverside.com',
    'mirrorservice.org',
    'mm.cfix.net',
    'mm.fcix.net',
    'mojang.com',
    'mozilla.org',
    'mutedeck.com',
    'mysql.com',
    'notion-static.com',
    'notion.so',
    'notion.com',
    'obvdev.at',
    'ocf.berkeley.edu',
    'office.com',
    'oobesaas.adobe.com',
    'openra.net',
    'oracle.com',
    'osuosl.org',
    'overwolf.com',
    'pathofexile.com',
    'perforce.com',
    'plugable.com',
    'poecdn.com',
    'pqrs.org',
    'proxmox.com',
    'prusa3d.com',
    'raspberrypi.com',
    'reaper.fm',
    'redhat.com',
    'remarkable.com',
    'rewind.ai',
    's3.amazonaws.com',
    'securew2.com',
    'signal.org',
    'siliconmotion.com',
    'skype.com',
    'slack-edge.com',
    'slack.com',
    'stclairsoft.com',
    'steampowered.com',
    'synaptics.com',
    'tableplus.com',
    'talos.dev',
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
    'xx.fbcdn.net',
    'yubico.com',
    'zoo.dev',
    'zoom.us',
    'zoomgov.com',
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
    'dl.google.com',
    'dl2.discordapp.net',
    'duckduckgo.com',
    'duetdownload.com',
    'dygma.com',
    'emacsformacosx.com',
    'emeet.com',
    'epson.com',
    'evernote.com',
    'fbcdn.net',
    'figma.com',
    'flipperzero.one',
    'fnord.com',
    'getkap.co',
    'gitbutler.com',
    'github.com',
    'go.dev',
    'imazing.com',
    'keybase.io',
    'kittycad.io',
    'krisp.ai',
    'mac.desktop.evernote.com',
    'macroplant.com',
    'mail.google.com',
    'mangoslab.blob.core.windows.net',
    'manual.canon',
    'manytricks.com',
    'maxon.net',
    'mimestream.com',
    'mnvoip.mm.fcix.net',
    'multipass.run',
    'mutedeck.com',
    'muteme.com',
    'new.expensify.com',
    'obdev.at',
    'obsidian.md',
    'obsproject.com',
    'opalcamera.com',
    'openai.com',
    'packages.openvpn.net',
    'persistent.oaistatic.com',
    'plugable.com',
    'plugable.com',
    'portswigger-cdn.net',
    'posit.co',
    'prerelease.keybase.io',
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
    'superhuman.com',
    'superkey.app',
    'tableplus.com',
    'textexpander.com',
    'tosmediaserver.schwab.com',
    'transmissionbt.com',
    'ubuntu.com',
    'ultimaker.com',
    'universal-blue.discourse.group',
    'us.ankerwork.com',
    'warp-releases.storage.googleapis.com',
    'wavebox.io',
    'welcome.adguard.com',
    'www.google.com',
    'www.granola.ai',
    'www.messenger.com',
    'www.raycast.com',
    'www.talos.dev',
    'zed.dev',
    'zoo.dev',
    'zoom.us'
  )
  -- Yes, these are meant to be fairly broad.
  AND host NOT LIKE '%.cdn.%.com'
  AND host NOT LIKE '%.edu'
  AND host NOT LIKE '%.org'
  AND host NOT LIKE '%.s3.%.amazonaws.com'
  AND host NOT LIKE '%release%.storage.googleapis.com'
  AND host NOT LIKE '%teams.microsoft.com'
  AND host NOT LIKE '%teams.microsoft.us'
  AND host NOT LIKE 'cdn%'
  AND host NOT LIKE 'dl-%'
  AND host NOT LIKE 'dl.%'
  AND host NOT LIKE 'download%'
  AND host NOT LIKE 'driver.%'
  AND host NOT LIKE 'github-production-release-asset-%.s3.amazonaws.com'
  AND host NOT LIKE 'mirror%'
  AND host NOT LIKE 'raycast-releases.%.r2.cloudflarestorage.com'
  AND host NOT LIKE 's3.%.amazonaws.com'
  AND host NOT LIKE 'software%'
  AND host NOT LIKE 'support%'
  AND host NOT LIKE 'www.google.%'
  AND ea.value NOT LIKE 'https://storage.googleapis.com/copilot-mac-releases/%'
  AND ea.value NOT LIKE 'https://storage.googleapis.com/kolide-k2-production-downloads-f414/%'
GROUP BY
  ea.value
