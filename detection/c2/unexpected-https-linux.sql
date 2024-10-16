-- Unexpected programs communicating over HTTPS (state-based)
--
-- This query is a bit awkward and hobbled due to the lack of osquery support
-- for looking up binary signatures in Linux.
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net often extra
-- platform: linux
SELECT
  s.remote_address,
  p.name,
  p.cgroup_path,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  s.local_address,
  s.local_port,
  s.state,
  hash.sha256,
  -- This intentionally avoids file.path, as it won't join across mount namespaces
  CONCAT (
    MIN(p.euid, 500),
    ',',
    REGEX_MATCH (p.path, '.*/(.*?)$', 1),
    ',',
    MIN(f.uid, 500),
    'u,',
    MIN(f.gid, 500),
    'g,',
    p.name
  ) AS exception_key
FROM
  process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON p.path = hash.path
WHERE
  protocol IN (6, 17)
  AND s.remote_port = 443
  AND s.remote_address NOT IN ('127.0.0.1', '::ffff:127.0.0.1', '::1')
  AND s.remote_address NOT LIKE 'fe80:%'
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND p.path != ''
  AND p.path NOT LIKE '/app/bin/%'
  AND p.path NOT LIKE '/usr/bin/%'
  AND p.path NOT LIKE '/usr/local/bin/%'
  AND p.path NOT LIKE '/opt/%'
  AND NOT exception_key IN (
    '0,agentbeat,0u,0g,agentbeat',
    '0,apk,u,g,apk',
    '0,applydeltarpm,0u,0g,applydeltarpm',
    '0,bash,0u,0g,bash',
    '0,bash,0u,0g,mkinitcpio',
    '0,bash,0u,0g,sh',
    '0,canonical-livepatchd,0u,0g,canonical-livep',
    '0,chainctl,0u,0g,chainctl',
    '0,chainctl,500u,500g,chainctl',
    '0,cmake,u,g,cmake',
    '0,containerd,u,g,containerd',
    '0,dirmngr,0u,0g,dirmngr',
    '0,dockerd,0u,0g,dockerd',
    '0,elastic-agent,0u,0g,elastic-agent',
    '0,elastic-agent,u,g,elastic-agent',
    '0,elastic-endpoint,0u,0g,elastic-endpoin',
    '0,filebeat,0u,0g,filebeat',
    '0,flatpak,0u,0g,flatpak',
    '0,flatpak-system-helper,0u,0g,flatpak-system-',
    '0,git-remote-http,0u,0g,git-remote-http',
    '0,go,0u,0g,go',
    '0,gtk4-update-icon-cache,0u,0g,gtk-update-icon',
    '0,http,0u,0g,https',
    '0,ir_agent,0u,0g,ir_agent',
    '0,kmod,0u,0g,depmod',
    '0,launcher,0u,0g,launcher',
    '0,launcher,500u,500g,launcher',
    '0,ldconfig,0u,0g,ldconfig',
    '0,make,0u,0g,make',
    '0,melange,500u,500g,melange',
    '0,metricbeat,0u,0g,metricbeat',
    '0,nessusd,0u,0g,nessusd',
    '0,nix,0u,0g,nix',
    '0,nix,0u,0g,nix-daemon',
    '0,orbit,0u,0g,orbit',
    '0,osqueryd,0u,0g,osqueryd',
    '0,packagekitd,0u,0g,packagekitd',
    '0,packetbeat,0u,0g,packetbeat',
    '0,pacman,0u,0g,pacman',
    '0,rapid7_endpoint_broker,0u,0g,rapid7_endpoint',
    '0,rpi-imager,0u,0g,rpi-imager',
    '0,skopeo,0u,0g,skopeo',
    '0,snapd,0u,0g,snapd',
    '0,systemctl,0u,0g,systemctl',
    '0,tailscaled,0u,0g,tailscaled',
    '0,tailscaled,500u,500g,tailscaled',
    '0,.tailscaled-wrapped,0u,0g,.tailscaled-wra',
    '0,velociraptor,0u,0g,velociraptor_cl',
    '0,yay,0u,0g,yay',
    '105,http,0u,0g,https',
    '106,geoclue,0u,0g,geoclue',
    '115,geoclue,0u,0g,geoclue',
    '120,fwupdmgr,0u,0g,fwupdmgr',
    '128,fwupdmgr,0u,0g,fwupdmgr',
    '129,fwupdmgr,0u,0g,fwupdmgr',
    '42,http,0u,0g,https',
    '500,1password,0u,0g,1password',
    '500,abrt-action-generate-core-backtrace,0u,0g,abrt-action-gen',
    '500,accountwizard,u,g,accountwizard',
    '500,act,0u,0g,act',
    '500,apk,500u,500g,apk',
    '500,apko,500u,500g,apko',
    '500,apko,u,g,apko',
    '500,apk,u,g,apk',
    '500,armcord,u,g,armcord',
    '500,aws,0u,0g,aws',
    '500,aws,500u,500g,aws',
    '500,bash,0u,0g,bash',
    '500,beeper,u,g,beeper',
    '500,bitwarden,u,g,bitwarden',
    '500,bom,500u,500g,bom',
    '500,bom-linux-amd64,500u,500g,bom-linux-amd64',
    '500,Brackets,0u,0g,Brackets',
    '500,brave,0u,0g,brave',
    '500,buildkitd,500u,500g,buildkitd',
    '500,buildkite-agent,500u,500g,buildkite-agent',
    '500,cargo,0u,0g,cargo',
    '500,cargo,500u,500g,cargo',
    '500,cargo,u,g,cargo',
    '500,chainctl,0u,0g,chainctl',
    '500,chainctl,500u,100g,chainctl',
    '500,chainctl,500u,493g,chainctl',
    '500,chainctl,500u,500g,chainctl',
    '500,chainctl,500u,500g,docker-credenti',
    '500,chrome,0u,0g,chrome',
    '500,chrome_crashpad_handler,0u,0g,chrome_crashpad',
    '500,chrome,u,g,chrome',
    '500,cilium,500u,123g,cilium',
    '500,cloud_sql_proxy,0u,0g,cloud_sql_proxy',
    '500,cockatrice,u,g,cockatrice',
    '500,code,0u,0g,code',
    '500,code,500u,500g,code',
    '500,code-oss,u,g,code-oss',
    '500,code,u,g,code',
    '500,com.docker.backend,0u,0g,com.docker.back',
    '500,com.docker.build,0u,0g,com.docker.buil',
    '500,com.docker.extensions,0u,0g,com.docker.exte',
    '500,containerd,u,g,containerd',
    '500,copilot-agent-linux,500u,500g,copilot-agent-l',
    '500,copilot-language-server,500u,500g,copilot-languag',
    '500,copy-from-gs,500u,500g,copy-from-gs',
    '500,cosign,500u,500g,cosign',
    '500,cosign-linux-amd64,0u,0g,cosign',
    '500,crane,0u,0g,crane',
    '500,crane,500u,500g,crane',
    '500,curl,0u,0g,curl',
    '500,deno,500u,500g,deno',
    '500,Discord,0u,0g,Discord',
    '500,Discord,u,g,Discord',
    '500,docker,0u,0g,docker',
    '500,docker-buildx,0u,0g,docker-buildx',
    '500,Docker Desktop,0u,0g,Docker Desktop',
    '500,drkonqi,0u,0g,drkonqi',
    '500,eksctl,0u,0g,eksctl',
    '500,eksctl,500u,500g,eksctl',
    '500,electron,0u,0g,electron',
    '500,evolution-addressbook-factory,0u,0g,evolution-addre',
    '500,evolution-calendar-factory,0u,0g,evolution-calen',
    '500,evolution-source-registry,0u,0g,evolution-sourc',
    '500,extension-manager,0u,0g,extension-manag',
    '500,firefox,0u,0g,firefox',
    '500,firefox,0u,0g,.firefox-wrappe',
    '500,firefox,0u,0g,Socket Process',
    '500,firefox-bin,500u,500g,firefox-bin',
    '500,firefox-bin,u,g,firefox-bin',
    '500,flameshot,0u,0g,flameshot',
    '500,flatpak,0u,0g,flatpak',
    '500,flatpak-oci-authenticator,0u,0g,flatpak-oci-aut',
    '500,flux,500u,500g,flux',
    '500,fulcio,500u,500g,fulcio',
    '500,gcsfuse,500u,500g,gcsfuse',
    '500,gdb,0u,0g,gdb',
    '500,geoclue,0u,0g,geoclue',
    '500,gh,0u,0g,gh',
    '500,gh-dash,500u,500g,gh-dash',
    '500,git,0u,0g,git',
    '500,github-desktop,0u,0g,github-desktop',
    '500,git-remote-http,0u,0g,git-remote-http',
    '500,git-remote-http,u,g,git-remote-http',
    '500,gitsign,0u,0g,gitsign',
    '500,gitsign,500u,0g,gitsign',
    '500,gitsign,500u,500g,gitsign',
    '500,gitsign-credential-cache,500u,500g,gitsign-credent',
    '500,gitsign,u,g,gitsign',
    '500,gjs-console,0u,0g,org.gnome.Maps',
    '500,gnome-recipes,0u,0g,gnome-recipes',
    '500,gnome-shell,0u,0g,gnome-shell',
    '500,gnome-software,0u,0g,gnome-software',
    '500,go,0u,0g,go',
    '500,go,500u,500g,go',
    '500,goa-daemon,0u,0g,goa-daemon',
    '500,___go_build_main_go,500u,500g,___go_build_mai',
    '500,gobuster,500u,500g,gobuster',
    '500,goland,500u,500g,goland',
    '500,go,u,g,go',
    '500,grafana,u,g,grafana',
    '500,grype,0u,0g,grype',
    '500,grype,500u,500g,grype',
    '500,gsd-datetime,0u,0g,gsd-datetime',
    '500,gvfsd-google,0u,0g,gvfsd-google',
    '500,gvfsd-http,0u,0g,gvfsd-http',
    '500,helm,0u,0g,helm',
    '500,htop,0u,0g,htop',
    '500,hugo,500u,500g,hugo',
    '500,io.elementary.appcenter,0u,0g,io.elementary.a',
    '500,istioctl,500u,500g,istioctl',
    '500,java,0u,0g,java',
    '500,java,500u,500g,java',
    '500,java,u,g,java',
    '500,jcef_helper,500u,500g,jcef_helper',
    '500,jetbrains-toolbox,u,g,jetbrains-toolb',
    '500,k6,500u,500g,k6',
    '500,k9s,0u,0g,k9s',
    '500,kbfsfuse,0u,0g,kbfsfuse',
    '500,keepassxc,u,g,keepassxc',
    '500,keybase,0u,0g,keybase',
    '500,Keybase,0u,0g,Keybase',
    '500,kioslave5,0u,0g,kioslave5',
    '500,ko,500u,500g,ko',
    '500,ko,u,g,ko',
    '500,kpromo,500u,500g,kpromo',
    '500,krel,500u,500g,krel',
    '500,krunner,0u,0g,krunner',
    '500,kubectl,0u,0g,kubectl',
    '500,kubectl,500u,500g,kubectl',
    '500,lens,0u,0g,lens',
    '500,less,0u,0g,less',
    '500,license-detector,500u,500g,license-detecto',
    '500,limactl,0u,0g,limactl',
    '500,limactl,500u,500g,limactl',
    '500,Logseq,u,g,Logseq',
    '500,losslesscut,500u,500g,losslesscut',
    '500,mconvert,500u,500g,mconvert',
    '500,mediawriter,u,g,mediawriter',
    '500,melange,500u,500g,melange',
    '500,melange,u,g,melange',
    '500,Melvor Idle,500u,500g,exe',
    '500,minikube,0u,0g,minikube',
    '500,msedge,0u,0g,msedge',
    '500,nami,500u,500g,nami',
    '500,nautilus,0u,0g,nautilus',
    '500,nerdctl,500u,500g,nerdctl',
    '500,nix,0u,0g,nix',
    '500,node,0u,0g,node',
    '500,node,0u,0g,.node2nix-wrapp',
    '500,node,0u,0g,npm install',
    '500,node,500u,500g,npm run start',
    '500,node,u,g,node',
    '500,nuclei,500u,500g,nuclei',
    '500,obs,0u,0g,obs',
    '500,obs-browser-page,0u,0g,obs-browser-pag',
    '500,obs-ffmpeg-mux,0u,0g,obs-ffmpeg-mux',
    '500,obs-ffmpeg-mux,u,g,obs-ffmpeg-mux',
    '500,obsidian,0u,0g,obsidian',
    '500,obsidian,u,g,obsidian',
    '500,obs,u,g,obs',
    '500,op,0u,500g,op',
    '500,packer-plugin-proxmox_v1.1.2_x5.0_linux_amd64,500u,500g,packer-plugin-p',
    '500,pacman,0u,0g,pacman',
    '500,php,0u,0g,php',
    '500,php8.1,0u,0g,php',
    '500,pingsender,0u,0g,pingsender',
    '500,plasma-discover,0u,0g,plasma-discover',
    '500,plasmashell,0u,0g,plasmashell',
    '500,podman,0u,0g,podman',
    '500,promoter,500u,500g,promoter',
    '500,publish-release,500u,500g,publish-release',
    '500,pycharm,500u,500g,pycharm',
    '500,python3,0u,0g,python3',
    '500,python3.10,0u,0g,aws',
    '500,python3.10,0u,0g,python',
    '500,python3.10,0u,0g,python3',
    '500,python3.11,0u,0g,aws',
    '500,python3.11,0u,0g,dnf',
    '500,python3.11,0u,0g,gnome-abrt',
    '500,python3.11,0u,0g,protonvpn',
    '500,python3.11,0u,0g,prowler',
    '500,python3.11,u,g,pip',
    '500,python3.12,0u,0g,dnf',
    '500,python3,500u,500g,python3',
    '500,python.test,500u,500g,python.test',
    '500,qemu-system-x86_64,0u,0g,qemu-system-x86',
    '500,reporter-ureport,0u,0g,reporter-urepor',
    '500,rpi-imager,0u,0g,rpi-imager',
    '500,rustup,0u,0g,rustup',
    '500,scoville,500u,500g,scoville',
    '500,signal-desktop,0u,0g,signal-desktop',
    '500,signal-desktop,u,g,signal-desktop',
    '500,skopeo,0u,0g,skopeo',
    '500,slack,0u,0g,slack',
    '500,slack,u,g,slack',
    '500,slirp4netns,0u,0g,slirp4netns',
    '500,slirp4netns,500u,500g,slirp4netns',
    '500,snap-store,0u,0g,snap-store',
    '500,snyk,500u,500g,snyk',
    '500,spotify,0u,0g,spotify',
    '500,spotify,500u,500g,spotify',
    '500,spotify,u,g,spotify',
    '500,ssh,0u,0g,ssh',
    '500,steam,500u,100g,steam',
    '500,steam,500u,500g,steam',
    '500,steamwebhelper,500u,100g,steamwebhelper',
    '500,steamwebhelper,500u,500g,steamwebhelper',
    '500,step,500u,500g,step',
    '500,step-cli,0u,0g,step',
    '500,stern,500u,500g,stern',
    '500,syft,500u,500g,syft',
    '500,syncthing,0u,0g,syncthing',
    '500,syncthing,u,g,syncthing',
    '500,synergy,0u,0g,synergy',
    '500,teams,0u,0g,teams',
    '500,telegram-desktop,u,g,telegram-deskto',
    '500,terraform,0u,0g,terraform',
    '500,terraform,500u,500g,terraform',
    '500,terraform-ls,500u,500g,terraform-ls',
    '500,thunderbird,0u,0g,thunderbird',
    '500,thunderbird-bin,u,g,thunderbird-bin',
    '500,thunderbird,u,g,thunderbird',
    '500,tidal-hifi,u,g,tidal-hifi',
    '500,tilt,500u,500g,tilt',
    '500,TJPP8_Vulkan,500u,500g,TJPP8_Vulkan',
    '500,todoist,0u,0g,todoist',
    '500,trivy,0u,0g,trivy',
    '500,trivy,500u,500g,trivy',
    '500,ubuntu-report,0u,0g,ubuntu-report',
    '500,WebKitNetworkProcess,0u,0g,WebKitNetworkPr',
    '500,wget,0u,0g,wget',
    '500,wine64-preloader,500u,500g,DaveTheDiver.ex',
    '500,wine64-preloader,500u,500g,Root.exe',
    '500,wolfictl,500u,500g,wolfictl',
    '500,wolfi-package-status,500u,500g,wolfi-package-s',
    '500,WPILibInstaller,500u,500g,WPILibInstaller',
    '500,writerside,500u,500g,writerside',
    '500,xmobar,0u,0g,xmobar',
    '500,yay,0u,0g,yay',
    '500,zdup,500u,500g,zdup',
    '500,zoom,0u,0g,zoom',
    '500,zoom.real,u,g,zoom.real'
  ) -- Exceptions where we have to be more flexible for the process name
  AND NOT exception_key LIKE '0,python3.%,0u,0g,dnf'
  AND NOT exception_key LIKE '0,python3.%,0u,0g,dnf-automatic'
  AND NOT exception_key LIKE '0,python3.%,500u,500g,dnf-automatic'
  AND NOT exception_key LIKE '0,python3.%,0u,0g,yum'
  AND NOT exception_key LIKE '500,python3.%,0u,0g,update-manager'
  AND NOT exception_key LIKE '500,cosign-%,500u,500g,cosign-%'
  AND NOT exception_key LIKE '500,node,0u,0g,npm exec %'
  AND NOT exception_key LIKE '500,node,0u,0g,npm install %'
  AND NOT exception_key LIKE '500,python3%,u,g,pip'
  AND NOT exception_key LIKE '500,python3.%,0u,0g,pip'
  AND NOT exception_key LIKE '500,terraform-provider-%,500u,500g,terraform-provi'
  AND NOT exception_key LIKE '500,terraform_%,500u,500g,terraform'
  AND NOT (
    exception_key LIKE '500,python3%,0u,0g,python%'
    AND (
      p.cmdline LIKE '%/gcloud.py %'
      OR p.cmdline LIKE "%pip install%"
      OR p.cmdline LIKE "%pip download%"
      OR p.cwd LIKE "/home/%/dev/%"
      OR p.cwd LIKE "/home/%/src/%"
      OR p.cwd LIKE "/home/%/github/%"
    )
  ) -- JetBrains
  AND NOT exception_key LIKE '500,___1go_build_%,500u,500g,___1go_build_%'
  AND NOT (
    p.path = '/usr/bin/mage'
    AND p.cmdline LIKE '/home/%/.magefile/%'
  )
  AND NOT p.path LIKE '/nix/store/%/bin/%'
  AND NOT (
    exception_key LIKE '500,%,500u,500g,%'
    AND p.path LIKE '/tmp/go-build%/exe/%'
  )
  AND NOT (
    exception_key = '0,curl,0u,0g,curl'
    AND p.cmdline LIKE 'curl --fail %'
  ) -- Exclude processes running inside of containers
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p.cgroup_path LIKE '/system.slice/system.slice:docker:%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%' -- Tests
  AND NOT p.path LIKE '/tmp/go-build%.test'
GROUP BY
  p.cmdline
