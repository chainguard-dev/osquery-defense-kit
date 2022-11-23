-- Indicative of a machine that probably needs a reboot for operating-system patches
SELECT
  os_version.name AS os_name,
  os_version.version AS os_version,
  kernel_info.version AS kernel,
  days AS uptime_days
FROM
  kernel_info,
  os_version,
  uptime
WHERE
  uptime.days > 60;
