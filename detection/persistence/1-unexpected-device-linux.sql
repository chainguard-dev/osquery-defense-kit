-- Finds unexpected device names, sometimes used for communication to a rootkit
--
-- references:
--   * https://attack.mitre.org/techniques/T1014/ (Rootkit)
--
-- Confirmed to catch revenge-rtkit
--
-- false positives:
--   * custom kernel modules
--
-- tags: persistent filesystem state
-- platform: linux
SELECT -- Remove numerals from device names
  -- Ugly, but better than dealing with multiple rounds of nesting COALESCE + REGEX_MATCH
  CONCAT (
    REPLACE(
      REPLACE(
        REPLACE(
          REPLACE(
            REPLACE(
              REPLACE(
                REPLACE(
                  REPLACE(REPLACE(REPLACE(path, "0", ""), "1", ""), "2", ""),
                  "3",
                  ""
                ),
                "4",
                ""
              ),
              "5",
              ""
            ),
            "6",
            ""
          ),
          "7",
          ""
        ),
        "8",
        ""
      ),
      "9",
      ""
    ),
    ",",
    file.type
  ) AS exception_key,
  file.*
FROM
  file
WHERE
  (
    path LIKE '/dev/%'
    OR directory LIKE '/dev/%'
    OR directory LIKE '/dev/%/.%'
    OR directory LIKE '/dev/.%'
  )
  AND path NOT LIKE '%/./%'
  AND path NOT LIKE '%/../%'
  AND exception_key NOT IN (
    '/dev/accel/,directory',
    '/dev/accel/accel,character',
    '/dev/acpi_thermal_rel,character',
    '/dev/autofs,character',
    '/dev/binder,character',
    '/dev/binderfs/,directory',
    '/dev/binderfs/binder-control,character',
    '/dev/binderfs/binder,character',
    '/dev/binderfs/features,directory',
    '/dev/binderfs/hwbinder,character',
    '/dev/binderfs/vndbinder,character',
    '/dev/block/,directory',
    '/dev/block/:,block',
    '/dev/bsg/,directory',
    '/dev/bsg/:::,character',
    '/dev/btrfs-control,character',
    '/dev/bus/,directory',
    '/dev/bus/usb,directory',
    '/dev/cdrom,block',
    '/dev/cec,character',
    '/dev/char/,directory',
    '/dev/char/:,character',
    '/dev/char/:,unknown',
    '/dev/console,character',
    '/dev/core,regular',
    '/dev/cpu_dma_latency,character',
    '/dev/cpu/,directory',
    '/dev/cpu/microcode',
    '/dev/cros_ec,character',
    '/dev/cuse,character',
    '/dev/data/,directory',
    '/dev/data/root,block',
    '/dev/dbc,character',
    '/dev/default/,directory',
    '/dev/disk/,directory',
    '/dev/gpt-auto-root,block',
    '/dev/ptp_kvm,character',
    '/dev/disk/by-diskseq,directory',
    '/dev/disk/by-dname,directory',
    '/dev/disk/by-id,directory',
    '/dev/disk/by-label,directory',
    '/dev/disk/by-loop-inode,directory',
    '/dev/disk/by-loop-ref,directory',
    '/dev/disk/by-partlabel,directory',
    '/dev/disk/by-partuuid,directory',
    '/dev/disk/by-path,directory',
    '/dev/disk/by-uuid,directory',
    '/dev/dm-,block',
    '/dev/dma_heap/,directory',
    '/dev/dma_heap/system,character',
    '/dev/dri/,directory',
    '/dev/dri/by-path,directory',
    '/dev/dri/card,character',
    '/dev/dri/renderD,character',
    '/dev/drm_dp_aux,character',
    '/dev/ecryptfs,character',
    '/dev/fb,character',
    '/dev/fd/,character',
    '/dev/fd/,directory',
    '/dev/fd/,fifo',
    '/dev/fd/,regular',
    '/dev/fd/,socket',
    '/dev/fd/,unknown',
    '/dev/full,character',
    '/dev/fuse,character',
    '/dev/gpiochip,character',
    '/dev/HID-SENSOR-e..auto,character',
    '/dev/hidraw,character',
    '/dev/hpet,character',
    '/dev/hugepages/,directory',
    '/dev/hugepages/libvirt,directory',
    '/dev/hwbinder,character',
    '/dev/hwrng,character',
    '/dev/ic-,character',
    '/dev/iio:device,character',
    '/dev/initctl,fifo',
    '/dev/input/,directory',
    '/dev/input/by-id,directory',
    '/dev/input/by-path,directory',
    '/dev/input/event,character',
    '/dev/input/js,character',
    '/dev/input/mice,character',
    '/dev/input/mouse,character',
    '/dev/iommu,character',
    '/dev/ipu-psys,character',
    '/dev/kfd,character',
    '/dev/kmsg,character',
    '/dev/kvm,character',
    '/dev/libmtp--,character',
    '/dev/libmtp--.,character',
    '/dev/log,socket',
    '/dev/loop-control,character',
    '/dev/loop,block',
    '/dev/lp,character',
    '/dev/mcelog,character',
    '/dev/media,character',
    '/dev/mei,character',
    '/dev/mem,character',
    '/dev/mqueue/,directory',
    '/dev/mtd,character',
    '/dev/mtd/,directory',
    '/dev/mtd/by-name,directory',
    '/dev/mtdro,character',
    '/dev/nbd,block',
    '/dev/nbdp,block',
    '/dev/net/,directory',
    '/dev/net/tun,character',
    '/dev/ngn,character',
    '/dev/ntsync,character',
    '/dev/null,character',
    '/dev/nvidia-caps/,directory',
    '/dev/nvidia-caps/nvidia-cap,character',
    '/dev/nvidia-modeset,character',
    '/dev/nvidia-uvm-tools,character',
    '/dev/nvidia-uvm,character',
    '/dev/nvidia,character',
    '/dev/nvidiactl,character',
    '/dev/nvme,character',
    '/dev/nvme-fabrics,character',
    '/dev/nvmen,block',
    '/dev/nvmenp,block',
    '/dev/nvram,character',
    '/dev/port,character',
    '/dev/ppp,character',
    '/dev/pps,character',
    '/dev/psaux,character',
    '/dev/ptmx,character',
    '/dev/ptp,character',
    '/dev/pts/,character',
    '/dev/pts/,directory',
    '/dev/pts/ptmx,character',
    '/dev/random,character',
    '/dev/rfkill,character',
    '/dev/rtc,character',
    '/dev/sda,block',
    '/dev/sdb,block',
    '/dev/sdc,block',
    '/dev/sdd,block',
    '/dev/sde,block',
    '/dev/sdf,block',
    '/dev/sdg,block',
    '/dev/sdh,block',
    '/dev/sdi,block',
    '/dev/serial/,directory',
    '/dev/serial/by-id,directory',
    '/dev/serial/by-path,directory',
    '/dev/sg,character',
    '/dev/sgx_provision',
    '/dev/shm/,directory',
    '/dev/shm/.org.chromium.Chromium.NjobT,regular',
    '/dev/shm/envoy_shared_memory_,regular',
    '/dev/shm/jack_db-,directory',
    '/dev/shm/libpod_lock,regular',
    '/dev/shm/libpod_rootless_lock_,regular',
    '/dev/shm/lttng-ust-wait--,regular',
    '/dev/shm/lttng-ust-wait-,regular',
    '/dev/snapshot,character',
    '/dev/snd/,directory',
    '/dev/snd/by-id,directory',
    '/dev/snd/by-path,directory',
    '/dev/snd/controlC,character',
    '/dev/snd/hwCD,character',
    '/dev/snd/pcmCDc,character',
    '/dev/snd/pcmCDp,character',
    '/dev/snd/seq,character',
    '/dev/snd/timer,character',
    '/dev/sr,block',
    '/dev/stderr,character',
    '/dev/stderr,fifo',
    '/dev/stdin,character',
    '/dev/stdin,fifo',
    '/dev/stdout,character',
    '/dev/stdout,fifo',
    '/dev/tee,character',
    '/dev/tpm,character',
    '/dev/tpmrm,character',
    '/dev/tty,character',
    '/dev/ttyUSB,character',
    '/dev/ttyACM,character',
    '/dev/ttyprintk,character',
    '/dev/ttyS,character',
    '/dev/ubuntu-vg/,directory',
    '/dev/udmabuf,character',
    '/dev/uhid,character',
    '/dev/uinput,character',
    '/dev/urandom,character',
    '/dev/usb/,directory',
    '/dev/usb/hiddev,character',
    '/dev/usbmon,character',
    '/dev/userfaultfd,character',
    '/dev/userio,character',
    '/dev/vcs,character',
    '/dev/vcsa,character',
    '/dev/vcsu,character',
    '/dev/vfio/,directory',
    '/dev/vfio/vfio,character',
    '/dev/vga_arbiter,character',
    '/dev/vgubuntu/,directory',
    '/dev/vgubuntu/incus-default,block',
    '/dev/vgubuntu/root,block',
    '/dev/vgubuntu/swap_,block',
    '/dev/vgubuntu/swap,block',
    '/dev/vhba_ctl,character',
    '/dev/vhci,character',
    '/dev/vhost-net,character',
    '/dev/vhost-net',
    '/dev/vhost-vsock,character',
    '/dev/vhost-vsock',
    '/dev/video,character',
    '/dev/vl-subdev,character',
    '/dev/vl/,directory',
    '/dev/vl/by-id,directory',
    '/dev/vl/by-path,directory',
    '/dev/vlloopback,character',
    '/dev/vndbinder,character',
    '/dev/vsock,character',
    '/dev/watchdog,character',
    '/dev/wwanat,character',
    '/dev/wwanmbim,character',
    '/dev/wwanqcdm,character',
    '/dev/zd,block',
    '/dev/zero,character',
    '/dev/zfs,character',
    '/dev/zram,block',
    '/dev/zvol/,directory',
    '/dev/zvol/rpool,directory'
  )
  AND NOT path LIKE '/dev/%-vg/%-lv'
  AND NOT path LIKE '/dev/mapper/%'
  AND NOT path LIKE '/dev/mqueue/us.zoom.aom.%'
  AND NOT path LIKE '/dev/shm/.com.google.Chrome.%'
  AND NOT path LIKE '/dev/shm/.com.microsoft.Edge.%'
  AND NOT path LIKE '/dev/shm/.org.chromium.Chromium.%'
  AND NOT path LIKE '/dev/shm/aomshm.%'
  AND NOT path LIKE '/dev/shm/%CefRaster%'
  AND NOT path LIKE '/dev/shm/xapp-tmp-%'
  AND NOT path LIKE '/dev/shm/byobu-%'
  AND NOT path LIKE '/dev/shm/lsp-catalog-%.lock'
  AND NOT path LIKE '/dev/shm/flatpak-com.brave.Browser-%'
  AND NOT path LIKE '/dev/shm/libv4l-%'
  AND NOT path LIKE '/dev/shm/sem.mp-%'
  AND NOT path LIKE '/dev/shm/sem.rpc%'
  AND NOT path LIKE '/dev/shm/u%-Shm_%'
  AND NOT path LIKE '/dev/shm/u%-ValveIPC%'
  AND NOT (
    directory = '/dev/shm/'
    AND type = 'regular'
    AND mode = '0666'
    AND uid IN (0, 1000, 1001)
    AND size IN (32, 4096)
  )
  AND NOT exception_key LIKE '/dev/vg%/,directory'
  AND NOT exception_key LIKE '/dev/vg%/root,block'
  AND NOT exception_key LIKE '/dev/vg%/swap%,block'
  AND NOT exception_key LIKE '/dev/%vg/,directory'
  AND NOT exception_key LIKE '/dev/%vg/root,block'
  AND NOT exception_key LIKE '/dev/%vg/swap%,block'
  AND NOT exception_key LIKE '/dev/default/%,block'
  AND NOT exception_key LIKE '/dev/shm/lsp-catalog-%.shm,regular'
GROUP BY
  exception_key
