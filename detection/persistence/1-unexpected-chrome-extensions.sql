-- Highlight chrome extensions with wide-ranging permissions that are not part of your whitelist
--
-- references:
--   * https://attack.mitre.org/techniques/T1176/ (Browser Extensions)
--
-- false positives:
--   * Almost unlimited: any extension that isn't on your whitelist
--
-- tags: persistent seldom browser
SELECT
  name,
  profile,
  chrome_extensions.description AS 'descr',
  persistent AS persists,
  CONCAT (
    "https://chromewebstore.google.com/detail/extension/",
    identifier
  ) AS ext_url,
  author,
  chrome_extensions.path,
  referenced AS in_config,
  file.ctime,
  file.btime,
  file.mtime,
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
    identifier
  ) AS exception_key,
  hash.sha256
FROM
  users
  CROSS JOIN chrome_extensions USING (uid)
  LEFT JOIN file ON chrome_extensions.path = file.path
  LEFT JOIN hash ON chrome_extensions.path = hash.path
WHERE
  state = 1
  AND (
    (
      from_webstore != 'true'
      AND (
        perms LIKE '%bookmarks%'
        OR perms LIKE "%http%"
        OR perms LIKE "%nativeMessaging%"
        OR perms LIKE "%pageCapture%"
        OR perms LIKE "%session%" -- Sigstore
        OR perms LIKE "%webRequest%"
      )
    )
    -- Can make requests and see interesting information
    OR (
      perms like '%webRequest%'
      OR perms LIKE '%dns%'
      AND (
        perms LIKE '%://*/%'
        OR perms LIKE '%<all_urls>%'
        OR perms LIKE '%blockchain%'
        OR perms LIKE '%clipboardRead%'
        OR perms LIKE '%coinbase%'
        OR perms LIKE '%cookies%'
        OR perms LIKE '%github.com%'
        OR perms LIKE '%google.com%'
        OR perms LIKE '%pageCapture%'
        OR perms LIKE '%privacy%'
        OR perms LIKE '%tabCapture%'
        OR perms LIKE '%tabs%'
        OR perms LIKE '%webNavigation%'
      )
    )
    -- Unusual permissions
    OR perms LIKE "%contentSettings%"
    OR perms LIKE "%history%"
    OR perms LIKE "%management%"
    OR perms LIKE "%nativeMessaging%"
    OR perms LIKE "%proxy%"
    OR perms LIKE "%vpnProvider%"
    OR perms LIKE "%webAuthenticationProxy%"
    OR perms LIKE '%debugger%'
    OR perms LIKE '%declarativeNetRequestFeedback%'
    OR perms LIKE '%desktopCapture%'
  )
  AND NOT exception_key IN (
    "true,GEN Digital Inc.,I don't care about cookies,fihnjjcciajhdojfnbdddfaoknhalnja",
    "true,OhMyGuus and Community (originally Daniel Kladnik),I still don't care about cookies,edibdbjcniadpccecjdfdjjppcpchdlm",
    'false,eff.software.projects@gmail.com,Privacy Badger,mkejgcgkdlddbggjhhflekkondicpnop',
    'false,privacybadger-owner@eff.org,Privacy Badger,mkejgcgkdlddbggjhhflekkondicpnop',
    'true,,Adblock for Youtube™,cmedhionkhpnakcndndgjdbohmhepckk',
    'true,,Adobe Acrobat: PDF edit, convert, sign tools,efaidnbmnnnibpcajpcglclefindmkaj',
    'true,,Allow CORS: Access-Control-Allow-Origin,lhobafahddgcelffkeicbaginigeejlf',
    'true,,Amplitude Event Explorer,acehfjhnmhbmgkedjmjlobpgdicnhkbp',
    'true,,Application Launcher For Drive (by Google),lmjegmlicamnimmfhcmpkclmigmmcbeh',
    'true,,Awesome Screen Recorder & Screenshot,nlipoenfbbikpbjkfpfillcgkoblgpmj',
    'true,,axe DevTools - Web Accessibility Testing,lhdoppojpmngadmnindnejefpokejbdd',
    'true,,Boomerang for Gmail,mdanidgdpmkimeiiojknlnekblgmpdll',
    'true,,Capital One Shopping: Save Now,nenlahapcbofgnanklpelkaejcehkggg',
    'true,,Chrome Capture - screenshot & GIF,ggaabchcecdbomdcnbahdfddfikjmphe',
    'true,,Chrome Remote Desktop,inomeogfingihgjfjlpeplalcfajhgai',
    'true,,Cisco Umbrella Chromebook client (Ext),jcdhmojfecjfmbdpchihbeilohgnbdci',
    'true,,Cisco Webex Extension,jlhmfgmfgeifomenelglieieghnjghma',
    'true,,Copper CRM for Gmail,hpfmedbkgaakgagknibnonpkimkibkla',
    'true,,Coupert - Automatic Coupon Finder & Cashback,mfidniedemcgceagapgdekdbmanojomk',
    'true,,CSP Evaluator,fjohamlofnakbnbfjkohkbdigoodcejf',
    'true,,DuckDuckGo Privacy Essentials,bkdgflcldnnnapblkhphbgpggdiikppg',
    'true,,DuckDuckGo Search & Tracker Protection,bkdgflcldnnnapblkhphbgpggdiikppg',
    'true,,EditThisCookie,fngmhnnpilhplaeedifhccceomclgfbg',
    'true,,Endpoint Verification,callobklhcbilhphinckomhgkigmfocg',
    'true,,Gem,bnbpceglddpnehbopmdjegpfinikcaoh',
    'true,,Go Links,gojgbkejhelijlkgpmlbbkklljgmfljj',
    'true,,Google Keep - Notes and Lists,hmjkmjkepdijhoojdojkdfohbdgmmhki',
    'true,,GoToTraining Screensharing,copcmbdalilphnaiajfmonkegedhkndd',
    'true,,Greenhouse Recruiting Chrome extension,naooopefdfeangnkgmjpklgblnfmbaea',
    'true,,Hippo Video: Video and Screen Recorder,cijidiollmnkegoghpfobabpecdkeiah',
    'true,,Honey: Automatic Coupons & Rewards,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,HubSpot Sales,oiiaigjnkhngdbnoookogelabohpglmd',
    'true,,iCloud Bookmarks,fkepacicchenbjecpbpbclokcabebhah',
    'true,,iCloud Passwords,pejdijmoenmkgeppbflobdenhhabjlaj',
    'true,,Kagi Privacy Pass,mendokngpagmkejfpmeellpppjgbpdaj',
    'true,,Kagi Search,cdglnehniifkbagbbombnjghhcihifij',
    'true,,Live Stream Downloader,looepbdllpjgdmkpdcdffhdbmpbcfekj',
    'true,,Loom – Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Media Hint,akipcefbjlmpbcejgdaopmmidpnjlhnb',
    'true,,Mettl Tests : Enable Screen Sharing,hkjemkcbndldepdbnbdnibeppofoooio',
    'true,,Microsoft Single Sign On,ppnbnpeolgkicgegkbkbjmhlideopiji',
    'true,,Moesif Origin/CORS Changer & API Logger,digfbfaphojjndkpccljibejjbppifbc',
    'true,,Newsletter Creator for Gmail - Flashissue,cihaednhfbocfdiflmpccekcmjepcnmb',
    'true,,Nooks,kbbdibmbjngifdgbmlleelghocpeimhe',
    'true,,NordVPN - VPN proxy for privacy and security,fjoaledfpmneenckfbpdfhkmimnjocfa',
    'true,,NoScript,doojmbjmlfjjnbmnoijecmcbfeoakpjm',
    'true,,Okta Browser Plugin,glnpjglilkicbckjpbgcfkogebgllemb',
    'true,,OneLogin for Google Chrome,ioalpmibngobedobkmbhgmadaphocjdn',
    'true,,Outreach Optimization on LinkedIn & Gmail,ngeodglgpmplepchhghijjncnikifaed',
    'true,,Page Analytics (by Google),fnbdnhhicmebfgdgglcdacdapkcihcoh',
    'true,,Poshmark | PosherVA,ofacfijogapplfgkoolmdojoieiemihl',
    'true,,Privacy Badger,pkehgijcmpdhfbdbbnkijodmdjhbjlgp',
    'true,,ProctorU,goobgennebinldhonaajgafidboenlkl',
    'true,,Ramp for Chrome,idefohglmnkliiadgfofeokcpjobdeik',
    'true,,Reddit Pixel Helper,ebgpcjlgganlidigifggjjiglghjnjcj',
    'true,,Reflect,kljfphapkgkjaiiddfmfpbdmeaplojge',
    'true,,Salesforce,jjghhkepijgakdammjldcbnjehfkfmha',
    'true,,SalesLoft Connect - Legacy,cffgjgigjfgjkfdopbobbdadaelbhepo',
    'true,,Save to Google Drive,gmbmikajjgmnabiglmofipeabaddhgne',
    'true,,Screen Recorder,hniebljpgcogalllopnjokppmgbhaden',
    'true,,Screenshot & Screen Video Record by Screeny,djekgpcemgcnfkjldcclcpcjhemofcib',
    'true,,Secure Browser - Online Proctoring Extension,aeindiojndlokkemcgakgpgbcmgonifn',
    'true,,Selenium IDE,mooikfkahbdckldjjndioackbalphokd',
    'true,,Soapbox —  Video Recorder,lmepjnndgdhcgphilomlfekmgnnmngbi',
    'true,,Solitaire,lkbhppfbabandkdmgjmifahoabeodiep',
    'true,,Surfshark VPN Extension,ailoabdmgclmfmhdagmlohpjlbpffblp',
    'true,,Talend API Tester - Free Edition,aejoelaoggembcahagimdiliamlcdmfm',
    'true,,Tamper Chrome (extension),hifhgpdkfodlpnlmlnmhchnkepplebkb',
    'true,,Tampermonkey,dhdgffkkebhmkfjojejmpbldmpobfkfo',
    'true,,TextExpander: Keyboard Shortcuts & Templates,mmfhhfjhpadoefoaahomoakamjcfcoil',
    'true,,Touch VPN - Secure and unlimited VPN proxy,bihmplhobchoageeokmgbdihknkjbknd',
    'true,,uBlock,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,,Video Downloader PLUS,njgehaondchbmjmajphnhlojfnbfokng',
    'true,,Video Downloader Professional,elicpjhcidhpjomhibiffojpinpmmpil',
    'true,,Vimium,dbepggeogbaibhgnhhndojpepiihcmeb',
    'true,,Web Developer,bfbameneiokkgbdmiekhjnmfkcnldhhm',
    'true,,WhatRuns,cmkdbmfndkfgebldhnkbfhlneefdaaip',
    'true,,Wistia Video Downloader,acbiaofoeebeinacmcknopaikmecdehl',
    'true,,Yesware Sales Engagement,gkjnkapjmjfpipfcccnjbjcbgdnahpjp',
    'true,,Zoom,hmbjbjdpkobdjplfobhljndfdfdipjhg',
    'true,,Zotero Connector,ekhagklcjbdpajgpjgmbionohlpdbjgc',
    'true,Adblock, Inc.,AdBlock — block ads across the web,gighmmpiobklfepjocnamgkkbiglidom',
    'true,Adguard Software Ltd,AdGuard AdBlocker,bgnkhhnnamicmpeenaelnjfhikgbkllg',
    'true,AgileBits,1Password Nightly – Password Manager,gejiddohjgogedgjnonbofjigllpkmbf',
    'true,AgileBits,1Password – Password Manager,aeblfdkhhhdcdjpifhhbdiojplfjncoa',
    'true,Aura,Aura,fjbgpaheigpmkbdkdfghmkbnkpeofmhh',
    'true,AwardWallet LLC,AwardWallet,lppkddfmnlpjbojooindbmcokchjgbib',
    'true,Benjamin Hollis,JSONView,gmegofmjomhknnokphhckolhcffdaihd',
    'true,BetterLogic <Dev@betterlogic>,Better History | Blacklist Mode,egehpkpgpgooebopjihjmnpejnjafefi',
    'true,BetterLogic <Dev@betterlogic>,Better History | Manage, Export & Delete History,egehpkpgpgooebopjihjmnpejnjafefi',
    'true,Bitwarden Inc.,Bitwarden - Free Password Manager,nngceckbapebfimnlniiiahkandclblb',
    'true,Bitwarden Inc.,Bitwarden Password Manager,nngceckbapebfimnlniiiahkandclblb',
    'true,Cartera,American Airlines AAdvantage® eShopping℠,dcdiajifnnbipfljbggcbbheipfdmgpo',
    'true,Cartera,Delta Air Lines SkyMiles® Shopping℠,mkgbnjpecbelajilbdeokhehjfbeglgf',
    'true,Cartera,United Airlines MileagePlus Shopping℠,apcjkhjbhapedgbekhlhdkidpohpkfne',
    'true,ExpressVPN,ExpressVPN: VPN proxy for a better internet,fgddmllnllkalaagkghckoinaemmogpe',
    'true,eyeo GmbH,Adblock Plus - free ad blocker,cfhdojbkjhnklbpkdaibdccddilifddb',
    'true,François Duprat,Mobile simulator - responsive testing tool,ckejmhbmlajgoklhgbapkiccekfoccmk',
    'true,Ghostery,Ghostery Tracker & Ad Blocker - Privacy AdBlock,mlomiejdfkolichcflejclcbmpeaniij',
    'true,GLIDER,Glider Proctoring,dcnidakmkbkbohdaelljpgdhmbbpbdbg',
    'true,GZ systems Ltd.,PureVPN Proxy - Best VPN for Chrome,bfidboloedlamgdmenmlbipfnccokknp',
    'true,https://metamask.io,MetaMask,nkbihfbeogaeaoehlefnkodbefgpgknn',
    'true,Kai Uwe Broulik <kde@privat.broulik.de>,Plasma Integration,cimiefiiaegbelhefglklhhakcgmhkai',
    'true,Keepa GmbH,Keepa - Amazon Price Tracker,neebplgakaahbhdphmkckjjcegoiijjo',
    'true,KeePassXC Team,KeePassXC-Browser,oboonakemofpalcgghocfoadofidjkkk',
    'true,Keeper Security, Inc.,Keeper® Password Manager & Digital Vault,bfogiafebfohielmmehodmfbbebbbpei',
    'true,LastPass,LastPass: Free Password Manager,hdokiejnpimakedhajhdlcegeplioahd',
    'true,Lydian AI <_start@lydian.ai>,Ghostwrite: ChatGPT Email Assistant,fbjnnjochaopepfjpngghafgnafebkjh',
    'true,Microsoft Corporation,Microsoft Autofill,fiedbfgcleddlbcmgdigjgdfcggjcion',
    'true,modhader@,ModHeader - Modify HTTP headers,idgpnmonknjnojddfkpgkljpfnnfcklj',
    'true,Olav Morken, Jaime Perez, Thijs Kinkhorst, Jan Köhler, Tim van Dijen,SAML-tracer,mpdajninpobndbfcldcmbpnnbhibjmch',
    'true,Opera Software AS,Rich Hints Agent,enegjkbbakeegngfapepobipndnebkdk',
    'true,Opera,Cashback Assistant,ompjkhnkeoicimmaehlcmgmpghobbjoj',
    'true,Quantier, LLC,Vim for Google Docs™,aphmodfjbhofkpibocbggkdfnpbpjmpp',
    'true,Rakuten,Rakuten: Get Cash Back For Shopping,chhjbpecpncaggjpdakmflnfcopglcmi',
    'true,Raymond Hill & contributors,uBlock Origin,cjpalhdlnbpafiamejdnhcphjbkeiagm',
    'true,Reddit Enhancement Suite contributors,Reddit Enhancement Suite,kbmfpngjjgdllneeigpgjifpgocmfgmb',
    'true,Symantec Corporation,Norton Password Manager,admmjipmmciaobhojoghlmleefbicajg',
    'true,Thomas Rientjes,Decentraleyes,ldpochfccmkkmhdbclfhpagapcfdljkj',
    'true,Wappalyzer,Wappalyzer - Technology profiler,gppongmhjkpfnbhagpmjfkannfbllamg',
    'true,Yuri Konotopov <ykonotopov@gnome.org>,GNOME Shell integration,gphhapmejobijbbhgpjhcjognlahblep',
    'true,Zinlab <sebastian@Zinlab>,Better History,egehpkpgpgooebopjihjmnpejnjafefi'
  )
  AND NOT (
    exception_key IN (
      'false,,Onion Browser Button,joijkphhgidknnmmaabfgjhjmgjiepia',
      'false,AgileBits,1Password – Password Manager,dppgmdbiimibapkepcbdbmkaabgiofem'
    )
    AND chrome_extensions.path LIKE '%/Microsoft Edge/%'
  )
GROUP BY
  exception_key
