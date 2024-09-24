-- Look for sketchy udev entries, inspired by sedexp
--
-- references:
--  * https://www.aon.com/en/insights/cyber-labs/unveiling-sedexp
--  * https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/
--
-- tags: volume filesystem
-- platform: linux
SELECT
  file.path,
  file.size,
  file.btime,
  file.ctime,
  file.mtime,
  hash.sha256,
  yara.*
FROM
  file
  JOIN yara ON file.path = yara.path
  LEFT JOIN hash ON file.path = hash.path
WHERE
  file.path IN (
    SELECT
      file.path
    FROM
      file
    WHERE
      file.path LIKE '/etc/udev/rules.d/%'
      OR file.path LIKE '/usr/lib/udev/rules.d/%'
      OR file.path LIKE '/lib/udev/rules.d/%'
      OR file.path LIKE '/usr/local/lib/udev/rules.d/%'
    GROUP BY
      file.inode
  )
  AND yara.sigrule = '
rule udev_memory_device_runner : critical {
    meta:
        description = "runs program once built-in memory device is created"
    strings:
        $action_add = "ACTION==\"add\""
        $major = "ENV{MAJOR}==\"1\""
        $run = "RUN+="
    condition:
        all of them
}

rule udev_at_runner : critical {
    meta:
        description = "runs program via at"
        reference = "https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/"
    strings:
        $add = "ACTION==\"add\""
        $run_at = "RUN+=\"/usr/bin/at "
        $run_at2 = "RUN+=\"at "
    condition:
        $add and any of ($run*)
}

rule udev_unusual_small_runner : high {
    meta:
        description = "small udev entry that runs program based on unusual parameters"
    strings:
        $action_run = "RUN+="
        $not_attrs = "ATTRS{"
        $not_kernel = "KERNEL=="
        $not_block = "SUBSYSTEM==\"block\""
        $not_bridge = "RUN+=\"bridge-network-interface\""
    condition:
        filesize < 96 and all of ($action*) and none of ($not*)
}

rule udev_major_runner : high {
    meta:
        description = "runs program once major device number is created, may have false-positives"
    strings:
        $action_add = "ACTION==\"add\""
        $major = "ENV{MAJOR}=="
        $run = "RUN+="
    condition:
        all of them
}'
  AND yara.count > 0
  AND NOT (
    matches = "udev_unusual_small_runner"
    AND file.path IN ('/usr/lib/udev/rules.d/99-cec-bluetooth.rules')
    AND file.size = 74
  )
