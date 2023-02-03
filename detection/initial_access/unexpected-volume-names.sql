-- Surfaces mounts with unexpected names
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
  REGEX_MATCH (mounts.path, '.*/(\w+)', 1) AS base_name,
  block_devices.vendor,
  block_devices.model,
  block_devices.uuid,
  file.path AS possible_path,
  hash.sha256 AS possible_sha256,
  ea.value AS possible_url
FROM mounts
  LEFT JOIN block_devices ON mounts.device = block_devices.name
  LEFT JOIN file ON file.path LIKE '/Users/%/Downloads/%' || REGEX_MATCH (mounts.path, '.*/(\w+)', 1) || '%.%'
  LEFT JOIN extended_attributes ea ON file.path = ea.path
  AND ea.key = 'where_from'
  LEFT JOIN hash ON file.path = hash.path
WHERE block_devices.type NOT IN ('Apple Fabric', 'PCI-Express')
  AND vol_name NOT LIKE '%backup%'
  AND vol_name NOT IN (
    'Slack',
    'Docker',
    'Google Chrome',
    'Figma Agent Installer',
    'WhatsApp Installer',
    'Snagit',
    'Bartender 4'
  )
  AND base_name NOT IN ('JDK', 'Aqua')
  AND vol_name NOT LIKE 'Signal %-universal'
  AND vol_name NOT LIKE 'Gephi %'
  AND mounts.path NOT LIKE '/private/tmp/KSInstallAction.%'
  AND mounts.path NOT IN ('/private/var/setup')
GROUP BY mounts.path