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
SELECT file.path,
  uid,
  gid,
  mode,
  mtime,
  ctime,
  btime,
  type,
  size,
  hash.sha256,
  magic.data
FROM file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE file.path IN (
    SELECT file.path
    FROM file
    WHERE file.path LIKE '/etc/udev/rules.d/%'
      OR file.path LIKE '/usr/lib/udev/rules.d/%'
      OR file.path LIKE '/lib/udev/rules.d/%'
      OR file.path LIKE '/usr/local/lib/udev/rules.d/%'
    GROUP BY file.inode
  )
  AND file.size < 180
  AND file.filename NOT IN (
    '10-switch.rules',
    '20-crystalhd.rules',
    '30-linksys-ae1200.rules',
    '40-redhat-disable-dell-ir-camera.rules',
    '45-i2c-tools.rules',
    '50-apport.rules',
    '60-bridge-network-interface.rules',
    '60-ddcutil-i2c.rules',
    '60-ddcutil.rules',
    '60-drm.rules',
    '60-incus-agent.rules',
    '60-net.rules',
    '60-rfkill.rules',
    '60-sunshine-ublue.rules',
    '61-accelerometer.rules',
    '61-mutter.rules',
    '65-persistent-net-nbft.rules',
    '66-saned.rules',
    '70-hypervfcopy.rules',
    '70-hypervkvp.rules',
    '70-hypervvss.rules',
    '70-rpiboot.rules',
    '70-spice-vdagentd.rules',
    '70-spice-webdavd.rules',
    '70-titan-key.rules',
    '71-alpha_imaging_technology_co-vr.rules',
    '71-astro_gaming-controllers.rules',
    '71-betop-controllers.rules',
    '71-nacon-controllers.rules',
    '71-pid_codes-controllers.rules',
    '71-sony-vr.rules',
    '72-intel-mipi-ipu6-camera.rules',
    '75-davincipanel.rules',
    '75-probe_mtd.rules',
    '75-sdx.rules',
    '51-ocfs2.rules',
    '81-kvm-rhel.rules',
    '85-hdparm.rules',
    '85-regulatory.rules',
    '88-neutron_hifi_dac.rules',
    '90-daxctl-device.rules',
    '90-rdma-umad.rules',
    '90-usb-microbit.rules',
    '90-wireshark-usbmon.rules',
    '91-drm-modeset.rules',
    '92-viia.rules',
    '95-udev-late.rules',
    '96-e2scrub.rules',
    '99-BlackmagicDevices.rules',
    '99-DavinciPanel.rules',
    '99-fuse3.rules',
    '70-libcamera.rules',
    '99-fuse.rules',
    '99-libsane1.rules',
    '99-lxd-agent.rules',
    '99-nfs.rules',
    '99-qemu-guest-agent.rules'
  )