-- Find unexpected regular files in /var/run
--
-- false positives:
--   * none known
--
-- references:
--   * https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent
-- platform: darwin
SELECT
  file.filename,
  uid,
  gid,
  mode,
  file.ctime,
  file.atime,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  file.directory = "/var/run"
  AND file.type = "regular"
  AND file.filename NOT IN (
    '.DidRunFLO',
    '.autoBackup',
    '.fctcompsupdate',
    'FirstBootAfterUpdate',
    'FirstBootCleanupHandled',
    'appfwd.pid',
    'auditd.pid',
    'automount.initialized',
    'bootpd.pid',
    'com.apple.DumpPanic.finishedPMUFaultHandling',
    'com.apple.DumpPanic.finishedThisBoot',
    'com.apple.WindowServer.didRunThisBoot',
    'com.apple.logind.didRunThisBoot',
    'com.apple.loginwindow.didRunThisBoot',
    'com.apple.mdmclient.daemon.didRunThisBoot',
    'com.apple.mobileassetd-MobileAssetBrain',
    'com.apple.parentalcontrols.webfilterctl.mutex',
    'com.apple.softwareupdate.availableupdatesupdated',
    'diskarbitrationd.pid',
    'fctc.s',
    'hdiejectd.pid',
    'installd.commit.pid',
    'kdc.pid',
    'prl_disp_service.pid',
    'prl_naptd.pid',
    'prl_watchdog-ebdba5702a20.pid',
    'resolv.conf',
    'rtadvd.pid',
    'signpost_reporter_running',
    'socketfilterfw.launchd',
    'syslog.pid',
    'systemkeychaincheck.done',
    'utmpx',
    'wifi'
  )
GROUP BY
  file.path;
