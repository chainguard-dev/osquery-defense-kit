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
    identifier
  ) AS exception_key,
  hash.sha256
FROM
  users
  CROSS JOIN chrome_extensions USING (uid)
  LEFT JOIN file ON chrome_extensions.path = file.path
  LEFT JOIN hash ON chrome_extensions.path = hash.path
WHERE
  (
    -- These extensions need the most review.
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
    'false,Anthony Feddersen - Chainguard, Inc.,Chainguard On-Call Chrome Extension,',
    'false,,base64 encode or decode selected text,',
    'false,,Google Chat,chfbpgnooceecdoohagngmjnndbbaeip', -- Deprecated Google Extension
    'false,,Google Chat,mdpkiolbdkhdjpekfbkbmhigcaggjagi', -- Deprecated Google Extension
    'false,,Google Cloud,gmdcbpephenfeelhagpbceidhdbobfpk', -- Deprecated Google Extension
    'false,,Google Drive,aghbiahbpaijignceidepookljebhfak', -- Deprecated Google Extension
    'false,,Google Photos,ncmjhecbjeaamljdfahankockkkdmedg', -- Deprecated Google Extension
    'false,julienv3@gmail.com,treasure-clicker,',
    'false,juverm@chainguard.dev,auto-close-gitsign,',
    'false,,YouTube,agimnkijcaahngcdmfeangaknmldooml', -- Deprecated Google Extension
    'true,Adaware,Safe Torrent Scanner,aegnopegbbhjeeiganiajffnalhlkkjb',
    'true,,Adblock for Youtube™,cmedhionkhpnakcndndgjdbohmhepckk',
    'true,Adblock, Inc.,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom',
    'true,,Add to Amazon Wish List,ciagpekplgpbepdgggflgmahnjgiaced',
    'true,,Adobe Acrobat: PDF edit, convert, sign tools,efaidnbmnnnibpcajpcglclefindmkaj',
    'true,AgileBits,1Password extension (desktop app required),aomjjhallfgjeglblehebfpbcfeobpgk',
    'true,AgileBits,1Password – Password Manager,aeblfdkhhhdcdjpifhhbdiojplfjncoa',
    'true,Alexander Shutau,Dark Reader,eimadpbcbfnmbkopoojfekhnkhdbieeh',
    'true,All uBlock contributors,uBlock - free ad blocker,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,,Application Launcher For Drive (by Google),lmjegmlicamnimmfhcmpkclmigmmcbeh',
    'true,,Bardeen - automate manual work,ihhkmalpkhkoedlmcnilbbhhbhnicjga',
    'true,,Bardeen - automate workflows with one click,ihhkmalpkhkoedlmcnilbbhhbhnicjga',
    'true,BetaFish,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom',
    'true,Bitwarden Inc.,Bitwarden - Free Password Manager,nngceckbapebfimnlniiiahkandclblb',
    'true,,BrowserStack Local,mfiddfehmfdojjfdpfngagldgaaafcfo',
    'true,CAD Team,Cookie AutoDelete,fhcgjolkccmbidfldomjliifgaodjagh',
    'true,,Canvas Blocker - Fingerprint Protect,nomnklagbgmgghhjidfhnoelnjfndfpd',
    'true,,Capital One Shopping: Add to Chrome for Free,nenlahapcbofgnanklpelkaejcehkggg',
    'true,,Caret,fljalecfjciodhpcledpamjachpmelml',
    'true,chromeos-recovery-tool-admin@google.com,Chromebook Recovery Utility,jndclpdbaamdhonoechobihbbiimdgai',
    'true,,Chrome RDP for Google Cloud Platform,mpbbnannobiobpnfblimoapbephgifkm',
    'true,,Chrome Remote Desktop,inomeogfingihgjfjlpeplalcfajhgai',
    'true,,Chrome Web Store Payments,nmmhkkegccagdldgiimedpiccmgmieda',
    'true,,Clear Cache,cppjkneekbjaeellbfkmgnhonkkjfpdn',
    'true,,ClickUp: Tasks, Screenshots, Email, Time,pliibjocnfmkagafnbkfcimonlnlpghj',
    'true,,Clockify Time Tracker,pmjeegjhjdlccodhacdgbgfagbpmccpe',
    'true,Clockwise Inc.,Clockwise: Team Time & Calendar Management,hjcneejoopafkkibfbcaeoldpjjiamog',
    'true,,Cloud9,nbdmccoknlfggadpfkmcpnamfnbkmkcp',
    'true,,Cloud Vision,nblmokgbialjjgfhfofbgfcghhbkejac',
    'true,,coLaboratory Notebook,pianggobfjcgeihlmfhfgkfalopndooo',
    'true,,ColorPick Eyedropper,ohcpnigalekghcmgcdcenkpelffpdolg',
    'true,,Copper CRM for Gmail,hpfmedbkgaakgagknibnonpkimkibkla',
    'true,,CSS Scan,gieabiemggnpnminflinemaickipbebg',
    "true,Daniel Kladnik @ kiboke studio,I don't care about cookies,fihnjjcciajhdojfnbdddfaoknhalnja",
    'true,,Datanyze Chrome Extension,mlholfadgbpidekmhdibonbjhdmpmafd',
    'true,,DEPRECATED Secure Shell App,pnhechapfaindjhompbnflcldabbghjo',
    'true,,DuckDuckGo Privacy Essentials,bkdgflcldnnnapblkhphbgpggdiikppg',
    'true,,EditThisCookie,fngmhnnpilhplaeedifhccceomclgfbg',
    'true,,Endpoint Verification,callobklhcbilhphinckomhgkigmfocg',
    'true,,Eno® from Capital One®,clmkdohmabikagpnhjmgacbclihgmdje',
    'true,,Espruino Web IDE,bleoifhkdalbjfbobjackfdifdneehpo',
    'true,,Event Merge for Google Calendar™,idehaflielbgpaokehlhidbjlehlfcep',
    'true,ExpressVPN,ExpressVPN: VPN proxy for a better internet,fgddmllnllkalaagkghckoinaemmogpe',
    'true,eyeo GmbH,Adblock Plus - free ad blocker,cfhdojbkjhnklbpkdaibdccddilifddb',
    'true,,Facebook Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc',
    'true,,Github Absolute Dates,iepecohjelcmdnahbddleblfphbaheno',
    'true,,Google Analytics Parameter Stripper,jbgedkkfkohoehhkknnmlodlobbhafge',
    'true,,Google Docs Offline,ghbmnnjooekpmoecnnnilnnbdlolhkhi',
    'true,,Google Drive,apdfllckaahabafndbhieahigkjlhalf',
    'true,,Google Hangouts,nckgahadagoaajjgafhacjanaoiihapd',
    'true,,Google Keep Chrome Extension,lpcaedmchfhocbbapmcbpinfpgnhiddi',
    'true,,Google Keep - Notes and Lists,hmjkmjkepdijhoojdojkdfohbdgmmhki',
    'true,,Google Mail Checker,mihcahmgecmbnbcchbopgniflfhgnkff',
    'true,,Google Optimize,bhdplaindhdkiflmbfbciehdccfhegci',
    'true,,Google Play Books,mmimngoggfoobjdlefbcabngfnmieonb',
    'true,,Grammarly: Grammar Checker and Writing App,kbfnbcaeplbcioakkpcpgfkobkghlhen',
    'true,,GSConnect,jfnifeihccihocjbfcfhicmmgpjicaec',
    'true,Guilherme Nascimento,Prevent Duplicate Tabs,eednccpckdkpojaiemedoejdngappaag',
    'true,,Honey: Automatic Coupons & Cash Back,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,Honey: Automatic Coupons & Rewards,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,HTTPS Everywhere,gcbommkclmclpchllfjekcdonpmejbdp',
    'true,https://metamask.io,MetaMask,nkbihfbeogaeaoehlefnkodbefgpgknn',
    'true,James Anderson,LeechBlock NG,blaaajhemilngeeffpbfkdjjoefldkok',
    'true,,Jitsi Meetings,kglhbbefdnlheedjiejgomgmfplipfeb',
    'true,,JSON Formatter,bcjindcccaagfpapjjmafapmmgkkhgoa',
    'true,Kas Elvirov,GitHub Gloc,kaodcnpebhdbpaeeemkiobcokcnegdki',
    'true,Keepa GmbH,Keepa - Amazon Price Tracker,neebplgakaahbhdphmkckjjcegoiijjo',
    'true,LastPass,LastPass: Free Password Manager,hdokiejnpimakedhajhdlcegeplioahd',
    'true,Leadjet,Leadjet - Make your CRM work on LinkedIn,kojhcdejfimplnokhhhekhiapceggamn',
    'true,,Lolli: Earn Bitcoin When You Shop,fleenceagaplaefnklabikkmocalkcpo',
    'true,,Loom – Free Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Loom – Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Lucidchart Diagrams,apboafhkiegglekeafbckfjldecefkhn',
    'true,,Markdown Preview Plus,febilkbfcbhebfnokafefeacimjdckgl',
    'true,Marker.io,Marker.io: Visual bug reporting for websites,jofhoojcehdmaiibilpcoofpdbbddkkl',
    'true,,Meta Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc',
    'true,NortonLifeLock Inc,Norton Safe Web,fnpbeacklnhmkkilekogeiekaglbmmka',
    'true,,NoScript,doojmbjmlfjjnbmnoijecmcbfeoakpjm',
    'true,,Notion Web Clipper,knheggckgoiihginacbkhaalnibhilkk',
    'true,,Office Editing for Docs, Sheets & Slides,gbkeegbaiigmenfmjfclcdgdpimamgkj',
    'true,,Okta Browser Plugin,glnpjglilkicbckjpbgcfkogebgllemb',
    'true,,OneTab,chphlpgkkbolifaimnlloiipkdnihall',
    'true,Opera Software AS,Rich Hints Agent,enegjkbbakeegngfapepobipndnebkdk',
    'true,,Outbrain Pixel Tracker,daebadnaphbiobojnpgcenlkgpihmbdc',
    'true,,Page Analytics (by Google),fnbdnhhicmebfgdgglcdacdapkcihcoh',
    'true,,Password Alert,noondiphcddnnabmjcihcjfbhfklnnep',
    'true,Pawel Psztyc,Advanced REST client,hgmloofddffdnphfgcellkdfbfbjeloo',
    'true,,Picture-in-Picture Extension (by Google),hkgfoiooedgoejojocmhlaklaeopbecg',
    'true,,Playback Rate,jgmkoefgnppfpagkhifpialkkkgnfgag',
    'true,,PlayTo for Chromecast™,jngkenaoceimiimeokpdbmejeonaaami',
    'true,,Postman,fhbjgbiflinjbdggehcddcbncdddomop',
    'true,,Privacy Badger,pkehgijcmpdhfbdbbnkijodmdjhbjlgp',
    'true,,Private Internet Access,jplnlifepflhkbkgonidnobkakhmpnmh',
    'true,,QuillBot for Chrome,iidnbdjijdkbmajdffnidomddglmieko',
    'true,Rakuten,Rakuten: Get Cash Back For Shopping,chhjbpecpncaggjpdakmflnfcopglcmi',
    'true,Raymond Hill & contributors,uBlock Origin,cjpalhdlnbpafiamejdnhcphjbkeiagm',
    'true,,React Developer Tools,fmkadmapgofadopljbjfkapdkoienihi',
    'true,,Reader Mode,llimhhconnjiflfimocjggfjdlmlhblm',
    'true,,Readwise Highlighter,jjhefcfhmnkfeepcpnilbbkaadhngkbi',
    'true,Reddit Enhancement Suite contributors,Reddit Enhancement Suite,kbmfpngjjgdllneeigpgjifpgocmfgmb',
    'true,,RSS Subscription Extension (by Google),nlbjncdgjeocebhnmkbbbdekmmmcbfjd',
    'true,,Save to Google Drive,gmbmikajjgmnabiglmofipeabaddhgne',
    'true,,Save to Pocket,niloccemoadcdkdjlinkgdfekeahmflj',
    'true,,Secure Shell,iodihamcpbpeioajjeobimgagajmlibd',
    'true,,Selenium IDE,mooikfkahbdckldjjndioackbalphokd',
    'true,,Send to Kindle for Google Chrome™,cgdjpilhipecahhcilnafpblkieebhea',
    'true,,Session Buddy,edacconmaakjimmfgnblocblbcdcpbko',
    'true,,Simple Tab Sorter,cgfpgnepljlgenjclbekbjdlgcodfmjp',
    'true,,Slack,jeogkiiogjbmhklcnbgkdcjoioegiknm',
    'true,,SSH for Google Cloud Platform,ojilllmhjhibplnppnamldakhpmdnibd',
    'true,,Super Dark Mode,nlgphodeccebbcnkgmokeegopgpnjfkc',
    'true,,Superhuman,dcgcnpooblobhncpnddnhoendgbnglpn',
    'true,,Tabli,igeehkedfibbnhbfponhjjplpkeomghi',
    'true,,Tab Wrangler,egnjhciaieeiiohknchakcodbpgjnchh',
    'true,,Tag Assistant Legacy (by Google),kejbdjndbnbjgmefkgdddjlbokphdefk',
    'true,Thomas Rientjes,Decentraleyes,ldpochfccmkkmhdbclfhpagapcfdljkj',
    'true,,Todoist for Chrome,jldhpllghnbhlbpcmnajkpdmadaolakh',
    'true,Tomas Popela, tpopela@redhat.com,Fedora User Agent,hojggiaghnldpcknpbciehjcaoafceil',
    'true,Tulio Ornelas <ornelas.tulio@gmail.com>,JSON Viewer,gbmdgpbipfallnflgajpaliibnhdgobh',
    'true,,Ubiquiti Device Discovery Tool,hmpigflbjeapnknladcfphgkemopofig',
    'true,,uBlock,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,,UET Tag Helper (by Microsoft Advertising),naijndjklgmffmpembnkfbcjbognokbf',
    'true,,User-Agent Switcher for Chrome,djflhoibgkdhkhhcedjiklpkjnoahfmg',
    'true,,Utime,kpcibgnngaaabebmcabmkocdokepdaki',
    'true,,Vimcal,akopimcimmdmklcmegcflfidpfegngke',
    'true,Vimeo,Vimeo Record - Screen & Webcam Recorder,ejfmffkmeigkphomnpabpdabfddeadcb',
    'true,,Vimium,dbepggeogbaibhgnhhndojpepiihcmeb',
    'true,,Vue.js devtools,nhdogjmejiglipccpnnnanhbledajbpd',
    'true,Wappalyzer,Wappalyzer - Technology profiler,gppongmhjkpfnbhagpmjfkannfbllamg',
    'true,,Windscribe - Free Proxy and Ad Blocker,hnmpcagpplmpfojmgmnngilcnanddlhb',
    'true,,WiseStamp email signature,pbcgnkmbeodkmiijjfnliicelkjfcldg',
    'true,,Zoom Scheduler,kgjfgplpablkjnlkjmjdecgdpfankdle'
  )
GROUP BY
  exception_key
