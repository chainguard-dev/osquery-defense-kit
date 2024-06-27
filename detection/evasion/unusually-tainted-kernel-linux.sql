-- Unusually tainted kernel - via a loaded kernel module
--
-- references:
--   * https://attack.mitre.org/techniques/T1014/ (Rootkit)
--   * https://docs.kernel.org/admin-guide/tainted-kernels.html
--
-- Confirmed to catch revenge-rtkit
--
-- false positives:
--   * custom kernel modules
--
-- tags: persistent kernel state
-- platform: linux
--
SELECT
  taint,
  taint & 65536 AS is_aux,
  taint & 8192 is_unsigned,
  taint & 4096 AS out_of_tree,
  taint & 512 AS kernel_warning,
  taint & 614 AS requested_by_userspace,
  taint & 8 AS force_unloaded,
  taint & 4 AS out_of_spec,
  taint & 2 AS force_loaded,
  taint & 1 AS proprietary,
  modules
FROM
  (
    SELECT
      sc.current_value AS taint,
      GROUP_CONCAT(km.name) AS modules
    FROM
      system_controls sc,
      kernel_modules km
    WHERE
      sc.name = "kernel.tainted"
    ORDER BY
      km.name ASC
  )
  -- 4096 is a signed, out of tree, open source driver
  -- 4097 is a signed, out of tree, proprietary driver
  -- 512 is a kernel warning
WHERE
  taint NOT IN (0, 512, 4096, 4097)
  -- Some day, folks will sign rootkits. That day isn't today.
  AND is_unsigned = 1
  AND NOT (
    (
      -- 12289 is an unsigned, out of tree, proprietary
      -- 12801 is an unsigned, out of tree, proprietary with kernel warning. not great.
      taint IN (12289, 12801)
      AND (
        modules LIKE "%,nvidia,%"
        OR modules LIKE "%,v42loopback,%"
        OR modules LIKE "%,wl,%"
      )
    )
    OR (
      -- 12352 is unsigned, out of tree, requested by user space
      -- 12289 is an unsigned, out of tree, proprietary
      taint IN (12352, 12289)
      AND modules LIKE "%,v4l2loopback,%"
    )
  )
