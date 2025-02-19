-- Funky systemd units, may be evidence of persistence
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/002/ (Create or Modify System Process: Systemd Service)
--   * https://www.cadosecurity.com/blog/spinning-yarn-a-new-linux-malware-campaign-targets-docker-apache-hadoop-redis-and-confluence
--   * https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/
--
-- false positives:
--   * home-made systemd files
--
-- tags: persistent filesystem systemd
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
  JOIN hash ON file.path = hash.path
WHERE
  file.path IN (
    SELECT DISTINCT
      (fragment_path)
    FROM
      systemd_units
    WHERE
      fragment_path LIKE "%.service"
      AND NOT fragment_path LIKE "/run/systemd/generator.late/%"
  )
  AND yara.sigrule = '
rule systemd_execstart_danger_path_val : high {
  meta:
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    description = "Starts from a dangerous-looking path"
  strings:
    $awkward = /ExecStart=\/(boot|var|tmp|dev|root)\/[\.\w\-\/]{0,32}/
  condition:
    filesize < 102400 and $awkward
}

rule systemd_execstart_elsewhere : medium {
  meta:
    description = "Starts from an unusual path"
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
    hash_2023_articles_https_pberba_github_io_security_2022_02_07_linux_threat_hunting_for_persistence_systemd_generators = "8c227f67a16162ffd5b453a478ced2950eba4cbe3b004c5cc935fb9551dc2289"
    hash_2024_2024_Spinning_YARN_yarn_fragments = "723326f8551f2a92ccceeec93859f58df380a3212e7510bc64181f2a0743231c"
  strings:
    $execstart = /ExecStart=\/[\w\/]{1,128}/
    $not_bin = "ExecStart=/bin/"
    $not_bin_true = "ExecStart=/bin/true"
    $not_etc_rcd = "ExecStart=/etc/rc.d/rc.local"
    $not_etc_rc_local = "ExecStart=/etc/rc.local"
    $not_init_d = "ExecStart=/etc/init.d/"
    $not_lib = "ExecStart=/lib/"
    $not_motd = "ExecStart=/etc/update-motd.d/"
    $not_opt = "ExecStart=/opt/"
    $not_sbin = "ExecStart=/sbin/"
    $not_usr_bin = "ExecStart=/usr/bin/"
    $not_usr_libexec = "ExecStart=/usr/libexec/"
    $not_usr_lib = "ExecStart=/usr/lib/"
    $not_usr_local = "ExecStart=/usr/local/"
    $not_usr_sbin = "ExecStart=/usr/sbin/"
    $not_usr_share = "ExecStart=/usr/share/"
    $not_etckeeper = "ExecStart=/etc/etckeeper/"
  condition:
    filesize < 102400 and $execstart and none of ($not_*)
}

rule systemd_execstop_elsewhere : medium {
  meta:
    ref = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
	description = "Runs program from unexpected directory at stop"
  strings:
    $execstop = /ExecStop=\/[\w\.\_\-]{2,64}/
    $not_lib = "ExecStop=/lib/"
    $not_opt = "ExecStart=/opt/"
    $not_sbin = "ExecStop=/sbin/"
    $not_usr_libexec = "ExecStop=/usr/libexec/"
    $not_usr_lib = "ExecStop=/usr/lib/"
    $not_usr_local = "ExecStop=/usr/local/"
    $not_usr_sbin = "ExecStop=/usr/sbin/"
    $not_usr_share = "ExecStop=/usr/share/"
  condition:
    filesize < 384 and $execstop and none of ($not*)
}

rule systemd_small_no_blank_lines : high {
  meta:
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
  strings:
    $execstart = "ExecStart"
    $blank = "\n\n"
    $not_dbus = "Type=dbus"
    $not_after = /After=\w/
    $not_before = /Before=\w{1,128}/
    $not_notify = "Type=notify"
  condition:
    filesize < 512 and $execstart and not $blank and none of ($not*)
}

rule systemd_small_multiuser_no_comments_or_documentation : high {
  meta:
    ref = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
	description = "systemd unit is undocumented"
  strings:
    $execstart = "ExecStart="
    $multiuser = "multi-user.target"
    $not_comment = "# "
    $not_documentation = "Documentation="
    $not_requires_socket = /Requires=.{0,64}socket/
    $not_condition_path = "Condition"
    $not_after = "After="
    $not_systemd = "ExecStart=systemd-"
    $not_output = "StandardOutput="
    $not_part_of = "PartOf="
    $not_dbus = "Type=dbus"
    $not_oneshot = "Type=oneshot"
    $not_lima = "Description=lima-guestagent"
    $not_check_sb = "Description=Service to check for secure boot key enrollment"
    $not_waydroid = "waydroid"
    $not_keyd = "ExecStart=/usr/local/bin/keyd"
  condition:
    filesize < 384 and $execstart and $multiuser and none of ($not_*)
}
rule systemd_small_no_output : high {
  meta:
	description = "Discards all logging output"
  strings:
    $output_null = "StandardOutput=null"
    $error_null = "StandardError=null"
    $not_input_null = "StandardInput=null"
    $not_syslog = "syslog"
    $not_before = "Before="
    $not_display = "WantedBy=display-manager.service"
  condition:
    filesize < 384 and ($output_null and $error_null) and none of ($not*)
}

rule systemd_small_multiuser_not_in_dependency_tree : high {
  meta:
    description = "Relies on nothing, nothing relies on it"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
  strings:
    $execstart = "ExecStart="
    $multiuser = "multi-user.target"
    $not_after = /After=\w/
    $not_before = /Before=\w{1,128}/
    $not_requires = /Requires=\w/
    $not_condition = "Condition"
    $not_oneshot = "Type=oneshot"
    $not_default = "DefaultDependencies=no"
    $not_env = "EnvironmentFile="
    $not_bus = "BusName="
    $not_idle = "Type=idle"
    $not_systemd = "ExecStart=systemd-"
    $not_lima = "Description=lima-guestagent"
    $not_check_sb = "Description=Service to check for secure boot key enrollment"
    $not_touchegg = /ExecStart=.*\/touchegg --/
    $not_keyd = "ExecStart=/usr/local/bin/keyd"
  condition:
    filesize < 384 and $execstart and $multiuser and none of ($not_*)
}

rule sytemd_small_type_forking_not_in_dep_tree : high {
  meta:
    hash_2023_Txt_Malware_Sustes_0e77 = "0e77291955664d2c25d5bfe617cec12a388e5389f82dee5ae4fd5c5d1f1bdefe"
    hash_2023_Unix_Malware_Kaiji_3e68 = "3e68118ad46b9eb64063b259fca5f6682c5c2cb18fd9a4e7d97969226b2e6fb4"
    hash_2023_Unix_Malware_Kaiji_f4a6 = "f4a64ab3ffc0b4a94fd07a55565f24915b7a1aaec58454df5e47d8f8a2eec22a"
  strings:
    $forking = "Type=forking"
    $not_after = /After=\w/
    $not_before = /Before=\w{1,128}/
    $not_condition = "ConditionPath"
    $not_oneshot = "Type=oneshot"
    $not_default_deps = "DefaultDependencies=no"
    $not_env = "EnvironmentFile="
    $not_bus = "BusName="
    $not_idle = "Type=idle"
    $not_systemd = "ExecStart=systemd-"
    $not_default_target = "WantedBy=default.target"
  condition:
    filesize < 384 and $forking and none of ($not_*)
}

rule systemd_small_restart_always : medium {
  meta:
    description = "service restarts no matter how many times it crashes"
    hash_2023_Downloads_kinsing = "05d02411668f4ebd576a24ac61cc84e617bdb66aa819581daa670c65f1a876f0"
  strings:
    $restart = "Restart=always"
    $not_syslog = "SyslogLevel="
    $not_gpl = "GPL-2.0-only"
    $not_after = /After=\w/
    $not_before = /Before=\w{1,128}/
    $not_notify = "Type=notify"
    $not_wanted_by = /WantedBy=\w{2,32}\.target/
  condition:
    filesize < 384 and $restart and none of ($not*)
}

rule systemd_small_short_description {
  meta:
    description = "Short or no description"
  strings:
    $execstart = "ExecStart="
    $short_desc = /Description=\n/
  condition:
    filesize < 384 and all of them
}

rule systemd_nice_execstart_restart_no_comment {
  meta:
    description = "Sets nice value and restarts always without comments, possible miner"
  strings:
    $has_execstart = "ExecStart="
    $has_restart = "Restart=always"
    $has_nice = "Nice="
    $not_comment = "#"
  condition:
    filesize < 4096 and all of ($has*) and none of ($not*)
}

rule usr_bin_execstop_shell : medium {
  meta:
    ref = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
	description = "Runs shell script at stop"
  strings:
    $execstop = /ExecStop=\/bin\/sh .{0,64}/
    $not_podman_logging = "/usr/bin/podman $LOGGING"
    $not_stderr = /ExecStop=\/bin\/sh .{0,64}set -eu/
    $not_nfs = /ExecStop=\/bin\/sh -c .\/usr\/sbin\/nfsdctl /
  condition:
    filesize < 4096 and $execstop and none of ($not*)
}

rule systemd_hidden_execstart : critical {
  meta:
  	description = "ExecStart references hidden file"
  strings:
    $path_top_bin = /ExecStart=\/\.[\w\/]+/
    $path_sub_bin = /ExecStart=\/\w[\w\/]*\/\.\w+/
    $path_arg_sub = /ExecStart=.* \/\w[\w\/]*\/\.\w+/
    $path_arg_top = /ExecStart=.* \/\.[\w\/]+/
    $not_autorelabel = "/.autorelabel"
    $not_exists = "ConditionPathExists"
    $not_ksysguard = "/.ksysguard/ksgrd_network_helper"
  condition:
  	any of ($path*) and none of ($not*)
}

rule systemd_hidden_execstop : critical {
  meta:
  	description = "ExecStop references hidden file"
  strings:
    $path_top_bin = /ExecStart=\/\.[\w\/]+/
    $path_sub_bin = /ExecStart=\/\w[\w\/]*\/\.\w+/
    $path_arg_sub = /ExecStart=.* \/\w[\w\/]*\/\.\w+/
    $path_arg_top = /ExecStart=.* \/\.[\w\/]+/

    $not_autorelabel = "/.autorelabel"
    $not_exists = "ConditionPathExists"
  condition:
  	any of ($path*) and none of ($not*)
}

rule systemd_hidden_working_directory : critical {
  meta:
  	description = "WorkingDirectory is a hidden"
  strings:
    $ref = /WorkingDirectory=.*\/\..*/
  condition:
	any of them
}
'
  AND yara.count > 0
