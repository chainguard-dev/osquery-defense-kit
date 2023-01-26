-- Notices volumes with unusual names
--
-- references:
--   * https://objective-see.org/blog/blog_0x4E.html (Shlayer)
--
-- tags: transient volume filesystem often
-- platform: darwin
SELECT mounts.path,
mounts.device,
mounts.type,
REGEX_MATCH (mounts.path, '.*/(.*)', 1) AS vol_name,
block_devices.vendor,
block_devices.model,
block_devices.uuid
FROM mounts
LEFT JOIN block_devices ON mounts.device = block_devices.name
WHERE block_devices.type NOT IN ('Apple Fabric', 'PCI-Express')
AND vol_name NOT LIKE '%backup%'
AND vol_name NOT IN (
  'Slack',
  'Docker',
  'WhatsApp Installer',
  'Bartender 4'
)
AND vol_name NOT LIKE 'Signal %-universal'
AND vol_name NOT LIKE 'Gephi %'