-- Unexpected small udev rule entries
--
-- Typically vendor-provided udev rules are more verbose.
--
-- references:
--   * https://documents.trendmicro.com/assets/white_papers/wp-operation-earth-berberoka.pdf
--   * https://attack.mitre.org/techniques/T1547/ (Boot or Logon Autostart Execution)
--
-- false positives:
--   * rules installed by 3rd party software
--
-- tags: persistent filesystem state
-- platform: linux
SELECT
  file.path,
  uid,
  gid,
  mode,
  mtime,
  ctime,
  type,
  size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  file.path LIKE '/usr/lib/udev/rules.d/%'
  AND file.size < 180
  AND file.path NOT IN (
    '/usr/lib/udev/rules.d/50-apport.rules',
    '/usr/lib/udev/rules.d/60-net.rules',
    '/usr/lib/udev/rules.d/60-rfkill.rules',
    '/usr/lib/udev/rules.d/61-mutter.rules',
    '/usr/lib/udev/rules.d/66-saned.rules',
    '/usr/lib/udev/rules.d/70-hypervfcopy.rules',
    '/usr/lib/udev/rules.d/70-hypervkvp.rules',
    '/usr/lib/udev/rules.d/70-hypervvss.rules',
    '/usr/lib/udev/rules.d/70-spice-vdagentd.rules',
    '/usr/lib/udev/rules.d/70-spice-webdavd.rules',
    '/usr/lib/udev/rules.d/71-alpha_imaging_technology_co-vr.rules',
    '/usr/lib/udev/rules.d/71-astro_gaming-controllers.rules',
    '/usr/lib/udev/rules.d/71-betop-controllers.rules',
    '/usr/lib/udev/rules.d/71-nacon-controllers.rules',
    '/usr/lib/udev/rules.d/71-sony-vr.rules',
    '/usr/lib/udev/rules.d/75-probe_mtd.rules',
    '/usr/lib/udev/rules.d/85-hdparm.rules',
    '/usr/lib/udev/rules.d/85-regulatory.rules',
    '/usr/lib/udev/rules.d/90-daxctl-device.rules',
    '/usr/lib/udev/rules.d/91-drm-modeset.rules',
    '/usr/lib/udev/rules.d/96-e2scrub.rules',
    '/usr/lib/udev/rules.d/99-BlackmagicDevices.rules',
    '/usr/lib/udev/rules.d/99-DavinciPanel.rules',
    '/usr/lib/udev/rules.d/99-fuse3.rules',
    '/usr/lib/udev/rules.d/99-fuse.rules',
    '/usr/lib/udev/rules.d/99-libsane1.rules',
    '/usr/lib/udev/rules.d/99-nfs.rules',
    '/usr/lib/udev/rules.d/99-qemu-guest-agent.rules'
  )
