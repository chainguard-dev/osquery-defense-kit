SELECT
  s.family, protocol, s.local_port, s.remote_port, s.local_address,
  s.remote_address, p.name, p.path, p.cmdline AS child_cmd, p.cwd, s.pid, s.net_namespace,
  p.parent AS parent_pid, pp.cmdline AS parent_cmd, hash.sha256,
  CONCAT(MIN(s.remote_port, 32768), ",", protocol, ",", MIN(p.uid, 500), ",", p.name, ',', signature.identifier, ',', signature.authority) AS exception_key
FROM process_open_sockets s
LEFT JOIN processes p ON s.pid = p.pid
LEFT JOIN processes pp ON pp.pid = p.parent
LEFT JOIN hash ON p.path = hash.path
LEFT JOIN signature ON p.path = signature.path
WHERE protocol > 0
AND s.remote_port > 0
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
AND s.state != 'LISTEN'
AND NOT (remote_port=53 AND protocol IN (6,17)) -- Like, everything uses DNS
-- Ignore most common application paths
AND p.path NOT LIKE '/Applications/%.app/Contents/%'
AND p.path NOT LIKE '/Library/Apple/System/Library/%'
AND p.path NOT LIKE '/System/Applications/%'
AND p.path NOT LIKE '/System/Library/%'
AND p.path NOT LIKE "/System/%"
AND p.path NOT LIKE "/usr/libexec/%"
AND p.path NOT LIKE "/usr/sbin/%"
AND NOT exception_key IN (
  '22,6,500,ssh,com.apple.openssh,Software Signing',
  '443,17,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
  '443,17,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
  '443,17,500,Reflect Helper,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
  '443,6,0,com.apple.MobileSoftwareUpdate.UpdateBrainService,com.apple.MobileSoftwareUpdate.UpdateBrainService,Software Signing',
  '443,6,0,launcher,launcher,Developer ID Application: Kolide Inc (YZ3EM74M78)',
  '443,6,500,bash,bash,',
  '443,6,500,cloud_sql_proxy,a.out,',
  '443,6,500,Code Helper,com.microsoft.VSCode.helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
  '443,6,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
  '443,6,500,Evernote Helper,com.evernote.Evernote.helper,Apple Mac OS Application Signing',
  '443,6,500,figma_agent,com.figma.agent,Developer ID Application: Figma, Inc. (T8RA8NE3B7)',
  '443,6,500,gitsign,a.out,',
  '443,6,500,go,org.golang.go,Developer ID Application: Google LLC (EQHXZ8M8AV)',
  '443,6,500,istioctl,a.out,',
  '443,6,500,ko,a.out,',
  '443,6,500,kubectl,a.out,',
  '443,6,500,Python,org.python.python,',
  '443,6,500,Reflect Helper,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
  '443,6,500,Reflect,app.reflect.ReflectDesktop,Developer ID Application: Reflect App, LLC (789ULN5MZB)',
  '443,6,500,sample,com.apple.dt.SamplingTools.sample,Software Signing',
  '443,6,500,steam_osx,com.valvesoftware.steam,Developer ID Application: Valve Corporation (MXGJJ98X76)',
  '443,6,500,terraform,terraform,Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
  '443,6,500,vim,vim,',
  '443,6,500,zsh,com.apple.zsh,Software Signing',
  '80,6,0,com.apple.MobileSoftwareUpdate.UpdateBrainService,com.apple.MobileSoftwareUpdate.UpdateBrainService,Software Signing'
)
AND NOT (p.name = 'syncthing' AND (remote_port IN (53,80,88,110,443,587,993,3306,7451) OR remote_port > 8000))
AND NOT (p.name IN ('chrome', 'Google Chrome Helper','Brave Browser Helper', 'Chromium Helper', 'Opera Helper') AND remote_port IN (443,80,8009,8080,8888,8443,5228,32211,53,10001,3478,19305,19306,19307,19308,19309))
AND NOT (p.name IN ('Mail', 'thunderbird', 'Spark', 'Notes') AND remote_port IN (143,443,587,465,585,993))
AND NOT (p.name IN ('spotify', 'Spotify Helper', 'Spotify') AND remote_port IN (53,443,8009,4070,32211))
AND NOT (remote_port=443 AND protocol=6 AND p.name LIKE 'terraform-provider-%')
AND NOT (remote_port=443 AND protocol=6 AND p.name LIKE 'kubectl.%')
AND NOT (p.cmdline LIKE '%google-cloud-sdk/lib/gcloud.py%' AND remote_port IN (80,43))
GROUP BY s.pid