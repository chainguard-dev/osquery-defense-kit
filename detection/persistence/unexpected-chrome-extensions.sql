-- Highlight chrome extensions with wide-ranging permissions that are not part of your whitelist
--
-- references:
--   * https://attack.mitre.org/techniques/T1176/
--
-- false positives:
--   * anything that isn't on your whitelist
--
-- tags: persistent seldom browser
SELECT name,
  profile,
  chrome_extensions.description AS 'descr',
  persistent AS persists,
  author,
  chrome_extensions.path,
  referenced AS in_config,
  file.ctime,
  from_webstore AS in_store,
  TRIM(CAST(permissions AS text)) AS perms,
  state AS 'enabled',
  CONCAT (
    from_webstore,
    ',',
    author,
    ',',
    name,
    ',',
    identifier,
    ',',
    TRIM(CAST(permissions AS text))
  ) AS exception_key,
  hash.sha256
FROM users
  CROSS JOIN chrome_extensions USING (uid)
  LEFT JOIN file ON chrome_extensions.path = file.path
  LEFT JOIN hash ON chrome_extensions.path = hash.path
WHERE (
    from_webstore != 'true'
    OR perms LIKE '%google.com%'
    OR perms LIKE '%chainguard%'
    OR perms LIKE '%github.com%'
    OR perms LIKE '%clipboardWrite%'
    OR perms LIKE '%<all_urls>%'
    OR perms LIKE '%tabs%'
    OR perms LIKE '%cookies%'
    OR perms LIKE '%://*/%'
  )
  AND enabled = 1
  AND exception_key NOT IN (
    'false,,Google Chat,mdpkiolbdkhdjpekfbkbmhigcaggjagi,', -- Deprecated Google Extension
    'false,,Google Cloud,gmdcbpephenfeelhagpbceidhdbobfpk,', -- Deprecated Google Extension
    'false,,Google Drive,aghbiahbpaijignceidepookljebhfak,', -- Deprecated Google Extension
    'false,,Google Photos,ncmjhecbjeaamljdfahankockkkdmedg,', -- Deprecated Google Extension
    'false,Anthony Feddersen - Chainguard, Inc.,Chainguard On-Call Chrome Extension,,background', -- TODO: Move to local exceptions list once osqtool supports them
    'true,,Adblock for Youtube™,cmedhionkhpnakcndndgjdbohmhepckk,storage, unlimitedStorage, webRequest, webRequestBlocking, <all_urls>',
    'true,,Add to Amazon Wish List,ciagpekplgpbepdgggflgmahnjgiaced,tabs, http://*/*, https://*/*',
    'true,,Adobe Acrobat: PDF edit, convert, sign tools,efaidnbmnnnibpcajpcglclefindmkaj,contextMenus, <all_urls>, tabs, downloads, nativeMessaging, webRequest, webRequestBlocking',
    'true,,BrowserStack Local,mfiddfehmfdojjfdpfngagldgaaafcfo,https://*.bsstag.com/*, https://*.browserstack.com/*, , clipboardWrite, app.window, storage',
    'true,,Capital One Shopping: Add to Chrome for Free,nenlahapcbofgnanklpelkaejcehkggg,tabs, contextMenus, storage, cookies, webRequest, webRequestBlocking, <all_urls>',
    'true,,Caret,fljalecfjciodhpcledpamjachpmelml,clipboardRead, clipboardWrite, contextMenus, storage, notifications, syncFileSystem, app.window.fullscreen.overrideEsc,',
    'true,,Chrome RDP for Google Cloud Platform,mpbbnannobiobpnfblimoapbephgifkm,clipboardRead, clipboardWrite, unlimitedStorage, storage, notifications, overrideEscFullscreen,',
    'true,,Chrome Remote Desktop,inomeogfingihgjfjlpeplalcfajhgai,clipboardRead, clipboardWrite, nativeMessaging, downloads, downloads.open',
    'true,,Chrome Web Store Payments,nmmhkkegccagdldgiimedpiccmgmieda,identity, webview, https://www.google.com/, https://www.googleapis.com/*, https://payments.google.com/payments/v4/js/integrator.js, https://sandbox.google.com/payments/v4/js/integrator.js',
    'true,,Clear Cache,cppjkneekbjaeellbfkmgnhonkkjfpdn,browsingData, cookies, <all_urls>',
    'true,,Vue.js devtools,nhdogjmejiglipccpnnnanhbledajbpd,<all_urls>, storage',
    'true,,ClickUp: Tasks, Screenshots, Email, Time,pliibjocnfmkagafnbkfcimonlnlpghj,alarms, identity, storage, unlimitedStorage, tabs, activeTab, notifications, contextMenus, downloads, <all_urls>, http://*/*, https://*/*',
    'true,,Clockify Time Tracker,pmjeegjhjdlccodhacdgbgfagbpmccpe,background, contextMenus, storage, tabs, activeTab, identity, idle, notifications, scripting, alarms',
    'true,,Cloud Vision,nblmokgbialjjgfhfofbgfcghhbkejac,clipboardWrite, contextMenus, notifications, file://*, <all_urls>',
    'true,,Cloud9,nbdmccoknlfggadpfkmcpnamfnbkmkcp,clipboardRead, clipboardWrite',
    'true,,coLaboratory Notebook,pianggobfjcgeihlmfhfgkfalopndooo,identity, , webview, , unlimitedStorage, storage, clipboardRead, clipboardWrite,',
    'true,,ColorPick Eyedropper,ohcpnigalekghcmgcdcenkpelffpdolg,activeTab, tabs, <all_urls>, storage, alarms',
    'true,,Copper CRM for Gmail,hpfmedbkgaakgagknibnonpkimkibkla,https://app.copper.com/, webRequest, webRequestBlocking, *://mail.google.com/*, tabs, storage, notifications, *://calendar.google.com/*',
    'true,,CSS Scan,gieabiemggnpnminflinemaickipbebg,storage, activeTab, <all_urls>, contextMenus, clipboardWrite',
    'true,,DEPRECATED Secure Shell App,pnhechapfaindjhompbnflcldabbghjo,clipboardRead, clipboardWrite, idle, notifications, storage, terminalPrivate, unlimitedStorage, fileSystemProvider, accessibilityFeatures.read, crashReportPrivate, metricsPrivate',
    'true,,DuckDuckGo Privacy Essentials,bkdgflcldnnnapblkhphbgpggdiikppg,contextMenus, webRequest, webRequestBlocking, :///*, webNavigation, activeTab, tabs, storage, <all_urls>, alarms',
    'true,,DuckDuckGo Privacy Essentials,bkdgflcldnnnapblkhphbgpggdiikppg,contextMenus, webRequest, webRequestBlocking, *://*/*, webNavigation, activeTab, tabs, storage, <all_urls>, alarms',
    'true,,EditThisCookie,fngmhnnpilhplaeedifhccceomclgfbg,tabs, <all_urls>, cookies, contextMenus, notifications, clipboardWrite, webRequest, webRequestBlocking',
    'true,,Endpoint Verification,callobklhcbilhphinckomhgkigmfocg,cookies, idle, nativeMessaging, storage, *://*.google.com/*, download, enterprise.reportingPrivate, browsingData, enterprise.deviceAttributes, enterprise.platformKeys, gcm, identity, identity.email, platformKeys',
    'true,,Eno® from Capital One®,clmkdohmabikagpnhjmgacbclihgmdje,activeTab, tabs, storage, cookies, webRequest, webRequestBlocking, https://*.capitalone.com/*, http://*.capitalone.com/*',
    'true,,Espruino Web IDE,bleoifhkdalbjfbobjackfdifdneehpo,serial, audioCapture, videoCapture, , storage, http://*/, https://*/',
    'true,,Event Merge for Google Calendar™,idehaflielbgpaokehlhidbjlehlfcep,https://www.google.com/calendar/*, https://calendar.google.com/*, storage',
    'true,,Facebook Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc,tabs, webNavigation, webRequest, webRequestBlocking, storage, identity, *://*/*, clipboardWrite',
    'true,,Google Analytics Parameter Stripper,jbgedkkfkohoehhkknnmlodlobbhafge,webNavigation, <all_urls>',
    'true,,WiseStamp email signature,pbcgnkmbeodkmiijjfnliicelkjfcldg,*://*.wisestamp.com/*, http://local.wisestamp.com:9081/*, https://local.wisestamp.com:8080/*, cookies',
    'true,,Loom – Free Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb,tabCapture, webNavigation, activeTab, contextMenus, storage, tabs, desktopCapture, notifications, cookies, *://*.useloom.com/, *://*.loom.com/, http://localhost/*',
    'true,,Google Docs Offline,ghbmnnjooekpmoecnnnilnnbdlolhkhi,alarms, storage, unlimitedStorage, https://docs.google.com/*, https://drive.google.com/*',
    'true,,Google Drive,apdfllckaahabafndbhieahigkjlhalf,clipboardRead, clipboardWrite, notifications',
    'true,,Google Hangouts,nckgahadagoaajjgafhacjanaoiihapd,alarms, background, cookies, idle, notifications, storage, system.display, tabs, *://*.google.com/*',
    'true,,Google Keep - Notes and Lists,hmjkmjkepdijhoojdojkdfohbdgmmhki,fileSystem, identity, identity.email, storage, unlimitedStorage, https://*.googleapis.com/, https://keep.google.com/media/, https://*.googleusercontent.com/, https://*.client-channel.google.com/client-channel, https://clients4.google.com/client-channel/client, https://www.google-analytics.com/, https://www.google.com/, https://play.google.com/log, geolocation, management, notifications',
    'true,,Google Keep Chrome Extension,lpcaedmchfhocbbapmcbpinfpgnhiddi,activeTab, identity, identity.email, contextMenus, file://*/*, http://*/, https://*/, storage, tabs, unlimitedStorage',
    'true,,Google Mail Checker,mihcahmgecmbnbcchbopgniflfhgnkff,alarms, tabs, webNavigation, *://*.google.com/',
    'true,,Google Optimize,bhdplaindhdkiflmbfbciehdccfhegci,storage, debugger, webRequest, webRequestBlocking, tabs, http://*/, https://*/',
    'true,,Google Play Books,mmimngoggfoobjdlefbcabngfnmieonb,clipboardWrite, unlimitedStorage',
    'true,,Grammarly: Grammar Checker and Writing App,kbfnbcaeplbcioakkpcpgfkobkghlhen,http://*/*, https://*/*, tabs, notifications, cookies, storage',
    'true,,GSConnect,jfnifeihccihocjbfcfhicmmgpjicaec,nativeMessaging, tabs, contextMenus',
    'true,,Honey: Automatic Coupons & Cash Back,bmnlcjabgnpnenekpadlanbbkooimhnj,cookies, storage, unlimitedStorage, webRequest, webRequestBlocking, http://*/*, https://*/*',
    'true,,HTTPS Everywhere,gcbommkclmclpchllfjekcdonpmejbdp,webNavigation, webRequest, webRequestBlocking, tabs, cookies, storage, *://*/*, ftp://*/*',
    'true,,Jitsi Meetings,kglhbbefdnlheedjiejgomgmfplipfeb,https://calendar.google.com/*',
    'true,,JSON Formatter,bcjindcccaagfpapjjmafapmmgkkhgoa,*://*/*, <all_urls>',
    'true,,Lolli: Earn Bitcoin When You Shop,fleenceagaplaefnklabikkmocalkcpo,<all_urls>, tabs, webNavigation, webRequest',
    -- SUS
    'true,,Loom – Free Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb,<all_urls>, tabCapture, webNavigation, activeTab, contextMenus, storage, tabs, desktopCapture, notifications, cookies, *://*.useloom.com/, *://*.loom.com/, http://localhost/*',
    'true,,Lucidchart Diagrams,apboafhkiegglekeafbckfjldecefkhn,unlimitedStorage, notifications, clipboardRead, clipboardWrite',
    'true,,Markdown Preview Plus,febilkbfcbhebfnokafefeacimjdckgl,storage, clipboardWrite, <all_urls>',
    'true,,Notion Web Clipper,knheggckgoiihginacbkhaalnibhilkk,activeTab, storage, cookies',
    'true,,Office Editing for Docs, Sheets & Slides,gbkeegbaiigmenfmjfclcdgdpimamgkj,clipboardRead, clipboardWrite, cookies, downloads, *://*.google.com/*, fileSystem, fileSystem.write, https://www.google-analytics.com/, https://www.googleapis.com/, identity, identity.email, metricsPrivate, storage, unlimitedStorage',
    'true,,OneTab,chphlpgkkbolifaimnlloiipkdnihall,chrome://favicon/, unlimitedStorage, storage, tabs, contextMenus, activeTab',
    'true,,Page Analytics (by Google),fnbdnhhicmebfgdgglcdacdapkcihcoh,storage, https://www.googleapis.com/, tabs, *://*/*, background, cookies, *://*.google.com/*, webNavigation, webRequest, *://*.google-analytics.com/*, *://stats.g.doubleclick.net/*',
    'true,,Password Alert,noondiphcddnnabmjcihcjfbhfklnnep,identity, identity.email, notifications, storage, tabs, <all_urls>',
    'true,,Picture-in-Picture Extension (by Google),hkgfoiooedgoejojocmhlaklaeopbecg,<all_urls>, storage',
    'true,,Postman,fhbjgbiflinjbdggehcddcbncdddomop,webview, system.display, http://*/*, https://*/*, contextMenus, unlimitedStorage, storage, fileSystem, fileSystem.write, notifications, identity,',
    'true,,Privacy Badger,pkehgijcmpdhfbdbbnkijodmdjhbjlgp,tabs, http://*/*, https://*/*, webNavigation, webRequest, webRequestBlocking, storage, privacy',
    'true,,Private Internet Access,jplnlifepflhkbkgonidnobkakhmpnmh,activeTab, storage, unlimitedStorage, cookies, webRequest, webRequestBlocking, proxy, privacy, contentSettings, alarms, background, downloads, <all_urls>',
    'true,,QuillBot for Chrome,iidnbdjijdkbmajdffnidomddglmieko,alarms, cookies, storage, activeTab, contextMenus, notifications, scripting',
    'true,,React Developer Tools,fmkadmapgofadopljbjfkapdkoienihi,file:///*, http://*/*, https://*/*',
    'true,,RSS Subscription Extension (by Google),nlbjncdgjeocebhnmkbbbdekmmmcbfjd,tabs, http://*/*, https://*/*, storage',
    'true,,Save to Google Drive,gmbmikajjgmnabiglmofipeabaddhgne,contextMenus, identity, printerProvider, notifications, pageCapture, storage, tabs, webRequest, <all_urls>',
    'true,,Save to Pocket,niloccemoadcdkdjlinkgdfekeahmflj,tabs, contextMenus, cookies, storage',
    'true,,Secure Shell,iodihamcpbpeioajjeobimgagajmlibd,clipboardRead, clipboardWrite, contextMenus, idle, notifications, storage, terminalPrivate, unlimitedStorage, fileSystemProvider, accessibilityFeatures.read, crashReportPrivate, metricsPrivate',
    'true,,Secure Shell,iodihamcpbpeioajjeobimgagajmlibd,clipboardRead, clipboardWrite, contextMenus, idle, notifications, storage, terminalPrivate, unlimitedStorage, fileSystemProvider, accessibilityFeatures.read',
    'true,,Send to Kindle for Google Chrome™,cgdjpilhipecahhcilnafpblkieebhea,tabs, <all_urls>, storage, unlimitedStorage',
    'true,,Session Buddy,edacconmaakjimmfgnblocblbcdcpbko,tabs, unlimitedStorage',
    'true,,Slack,jeogkiiogjbmhklcnbgkdcjoioegiknm,unlimitedStorage, notifications, clipboardRead, clipboardWrite',
    'true,,SSH for Google Cloud Platform,ojilllmhjhibplnppnamldakhpmdnibd,clipboardRead, clipboardWrite',
    'true,,Super Dark Mode,nlgphodeccebbcnkgmokeegopgpnjfkc,storage, <all_urls>, contextMenus',
    'true,,Superhuman,dcgcnpooblobhncpnddnhoendgbnglpn,background, gcm, notifications, storage, system.cpu, system.display, system.memory, tabs, unlimitedStorage, <all_urls>',
    'true,,Tab Wrangler,egnjhciaieeiiohknchakcodbpgjnchh,contextMenus, sessions, storage, tabs',
    'true,,Tabli,igeehkedfibbnhbfponhjjplpkeomghi,storage, tabs, bookmarks, chrome://favicon/*',
    'true,,Tag Assistant Legacy (by Google),kejbdjndbnbjgmefkgdddjlbokphdefk,identity, storage, tabs, webNavigation, webRequestBlocking, webRequest, http://*/, https://*/',
    'true,,Todoist for Chrome,jldhpllghnbhlbpcmnajkpdmadaolakh,storage, tabs, contextMenus, webRequest, webRequestBlocking, http://*.todoist.com/*, https://*.todoist.com/*, background, declarativeNetRequestWithHostAccess',
    'true,,Ubiquiti Device Discovery Tool,hmpigflbjeapnknladcfphgkemopofig,system.network, clipboardRead, clipboardWrite, notifications, storage, unlimitedStorage,',
    'true,,UET Tag Helper (by Microsoft Advertising),naijndjklgmffmpembnkfbcjbognokbf,activeTab, downloads, tabs, webNavigation, webRequest, http://*/, https://*/',
    'true,,Utime,kpcibgnngaaabebmcabmkocdokepdaki,clipboardWrite, contextMenus, notifications',
    'true,,Vimium,dbepggeogbaibhgnhhndojpepiihcmeb,tabs, bookmarks, history, clipboardRead, storage, sessions, notifications, webNavigation, <all_urls>',
    'true,,Windscribe - Free Proxy and Ad Blocker,hnmpcagpplmpfojmgmnngilcnanddlhb,<all_urls>, proxy, management, tabs, webRequest, webRequestBlocking, activeTab, storage, unlimitedStorage, contextMenus, privacy, webNavigation, notifications, cookies',
    'true,,Zoom Scheduler,kgjfgplpablkjnlkjmjdecgdpfankdle,unlimitedStorage, https://www.google.com/calendar/*, https://www.google.com/recaptcha/*, https://www.gstatic.com/recaptcha/*, https://calendar.google.com/calendar/*, https://*.zoom.us/*, https://*.zoom.com/*',
    'true,Adaware,Safe Torrent Scanner,aegnopegbbhjeeiganiajffnalhlkkjb,storage, tabs',
    'true,AgileBits,1Password – Password Manager,aeblfdkhhhdcdjpifhhbdiojplfjncoa,<all_urls>, contextMenus, downloads, idle, management, nativeMessaging, notifications, privacy, tabs, webNavigation, webRequest, webRequestBlocking',
    'true,AgileBits,1Password extension (desktop app required),aomjjhallfgjeglblehebfpbcfeobpgk,contextMenus, nativeMessaging, storage, tabs, webRequest, webRequestBlocking, http://*/*, https://*/*',
    'true,Alexander Shutau,Dark Reader,eimadpbcbfnmbkopoojfekhnkhdbieeh,alarms, fontSettings, storage, tabs, <all_urls>',
    'true,All uBlock contributors,uBlock - free ad blocker,epcnnfbjfcgphgdmggkamkmgojdagdnn,contextMenus, storage, tabs, unlimitedStorage, webNavigation, webRequest, webRequestBlocking, <all_urls>',
    'true,BetaFish,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom,tabs, <all_urls>, contextMenus, webRequest, webRequestBlocking, webNavigation, storage, unlimitedStorage, notifications, idle, alarms',
    'true,Bitwarden Inc.,Bitwarden - Free Password Manager,nngceckbapebfimnlniiiahkandclblb,tabs, contextMenus, storage, unlimitedStorage, clipboardRead, clipboardWrite, idle, http://*/*, https://*/*, webRequest, webRequestBlocking',
    'true,chromeos-recovery-tool-admin@google.com,Chromebook Recovery Utility,jndclpdbaamdhonoechobihbbiimdgai,https://dl.google.com/dl/edgedl/chromeos/recovery/recovery2.json, https://dl.google.com/dl/edgedl/chromeos/recovery/cloudready_recovery2.json, https://www.google-analytics.com/, chromeosInfoPrivate, feedbackPrivate, fileSystem, imageWriterPrivate, metricsPrivate, storage',
    'true,Clockwise Inc.,Clockwise: Team Time & Calendar Management,hjcneejoopafkkibfbcaeoldpjjiamog,activeTab, https://calendar.google.com/calendar/*',
    'true,eyeo GmbH,Adblock Plus - free ad blocker,cfhdojbkjhnklbpkdaibdccddilifddb,<all_urls>, contextMenus, notifications, storage, tabs, unlimitedStorage, webNavigation, webRequest, webRequestBlocking',
    'true,Guilherme Nascimento,Prevent Duplicate Tabs,eednccpckdkpojaiemedoejdngappaag,tabs',
    'true,https://metamask.io,MetaMask,nkbihfbeogaeaoehlefnkodbefgpgknn,storage, unlimitedStorage, clipboardWrite, http://localhost:8545/, https://*.infura.io/, https://chainid.network/chains.json, https://lattice.gridplus.io/*, activeTab, webRequest, *://*.eth/, notifications',
    'true,James Anderson,LeechBlock NG,blaaajhemilngeeffpbfkdjjoefldkok,downloads, contextMenus, storage, tabs, unlimitedStorage, webNavigation',
    'true,Keepa GmbH,Keepa - Amazon Price Tracker,neebplgakaahbhdphmkckjjcegoiijjo,storage, cookies, contextMenus, *://*.keepa.com/*, *://*.amazon.com/*, *://*.amzn.com/*, *://*.amazon.co.uk/*, *://*.amazon.de/*, *://*.amazon.fr/*, *://*.amazon.it/*, *://*.amazon.ca/*, *://*.amazon.com.mx/*, *://*.amazon.es/*, *://*.amazon.co.jp/*, *://*.amazon.in/*, *://*.amazon.com.br/*, *://*.amazon.nl/*, *://*.amazon.com.au/*',
    'true,LastPass,LastPass: Free Password Manager,hdokiejnpimakedhajhdlcegeplioahd,tabs, idle, notifications, contextMenus, unlimitedStorage, webRequest, webNavigation, webRequestBlocking, http://*/*, https://*/*, chrome://favicon/*',
    'true,NortonLifeLock Inc,Norton Safe Web,fnpbeacklnhmkkilekogeiekaglbmmka,tabs, background, webNavigation, storage, <all_urls>, webRequest, webRequestBlocking, downloads, notifications',
    'true,Opera Software AS,Rich Hints Agent,enegjkbbakeegngfapepobipndnebkdk,boosterPrivate, cashbackPrivate, browserSidebarPrivate, downloads, history, limitersPrivate, management, operaBrowserPrivate, powerSavePrivate, richHintsAgentPrivate, settingsPrivate, speeddialPrivate, storage, tabs, uiTrackerPrivate, windows, http://*/, https://*/',
    'true,Pawel Psztyc,Advanced REST client,hgmloofddffdnphfgcellkdfbfbjeloo,<all_urls>, storage, unlimitedStorage, identity, syncFileSystem,',
    'true,Raymond Hill & contributors,uBlock Origin,cjpalhdlnbpafiamejdnhcphjbkeiagm,contextMenus, privacy, storage, tabs, unlimitedStorage, webNavigation, webRequest, webRequestBlocking, <all_urls>',
    'true,Reddit Enhancement Suite contributors,Reddit Enhancement Suite,kbmfpngjjgdllneeigpgjifpgocmfgmb,https://*.reddit.com/*, tabs, history, storage, unlimitedStorage, webRequest',
    'true,Tulio Ornelas <ornelas.tulio@gmail.com>,JSON Viewer,gbmdgpbipfallnflgajpaliibnhdgobh,*://*/*, <all_urls>',
    'true,Wappalyzer,Wappalyzer - Technology profiler,gppongmhjkpfnbhagpmjfkannfbllamg,cookies, storage, tabs, webRequest, webNavigation, http://*/*, https://*/*'
  )
GROUP BY exception_key