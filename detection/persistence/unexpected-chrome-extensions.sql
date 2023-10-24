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
        perms LIKE "%nativeMessaging%"
        OR perms LIKE '%bookmarks%'
        OR perms LIKE "%pageCapture%"
        OR perms LIKE "%session%" -- Sigstore
        OR perms LIKE "%http%"
        OR perms LIKE "%webRequest%"
      )
    )
    OR (
      perms LIKE '%://*/%'
      OR perms LIKE '%<all_urls>%'
      OR perms LIKE '%clipboardRead%'
      OR perms LIKE '%cookies%'
      OR perms LIKE '%coinbase%'
      OR perms LIKE '%blockchain%'
      OR perms LIKE '%debugger%'
      OR perms LIKE '%declarativeNetRequestFeedback%'
      OR perms LIKE '%desktopCapture%'
      OR perms LIKE '%github.com%'
      OR perms LIKE '%google.com%'
      OR perms LIKE "%history%"
      OR perms LIKE "%nativeMessaging%"
      OR perms LIKE "%proxy%"
      OR perms LIKE "%webAuthenticationProxy%"
      OR perms LIKE "%management%"
    )
  )
  AND NOT exception_key IN (
    "true,Daniel Kladnik @ kiboke studio,I don't care about cookies,fihnjjcciajhdojfnbdddfaoknhalnja",
    "true,Gareth Stephenson,My O'Reilly Downloader,deebiaolijlopiocielojiipnpnaldlk",
    'true,,Acorns Earn,facncfnojagdpibmijfjdmhkklabakgd',
    'true,,Adblock for Youtube™,cmedhionkhpnakcndndgjdbohmhepckk',
    'true,,Add to Amazon Wish List,ciagpekplgpbepdgggflgmahnjgiaced',
    'true,,Adobe Acrobat: PDF edit, convert, sign tools,efaidnbmnnnibpcajpcglclefindmkaj',
    'true,,Application Launcher For Drive (by Google),lmjegmlicamnimmfhcmpkclmigmmcbeh',
    'true,,Bardeen - automate manual work,ihhkmalpkhkoedlmcnilbbhhbhnicjga',
    'true,,Bardeen - automate workflows with one click,ihhkmalpkhkoedlmcnilbbhhbhnicjga',
    'true,,Bionic Reading,kdfkejelgkdjgfoolngegkhkiecmlflj',
    'true,,BlockSite: Block Websites & Stay Focused,eiimnmioipafcokbfikbljfdeojpcgbh',
    'true,,Browsec VPN - Free VPN for Chrome,omghfjlpggmjjaagoclmmobgdodcjboh',
    'true,,BrowserStack Local,mfiddfehmfdojjfdpfngagldgaaafcfo',
    'true,,CSS Scan,gieabiemggnpnminflinemaickipbebg',
    'true,,Canvas Blocker - Fingerprint Protect,nomnklagbgmgghhjidfhnoelnjfndfpd',
    'true,,Capital One Shopping: Add to Chrome for Free,nenlahapcbofgnanklpelkaejcehkggg',
    'true,,Caret,fljalecfjciodhpcledpamjachpmelml',
    'true,,Chrome Capture - Gif & Screenshot tool,ggaabchcecdbomdcnbahdfddfikjmphe',
    'true,,Chrome RDP for Google Cloud Platform,mpbbnannobiobpnfblimoapbephgifkm',
    'true,,Chrome Remote Desktop,inomeogfingihgjfjlpeplalcfajhgai',
    'true,,Chrome Web Store Payments,nmmhkkegccagdldgiimedpiccmgmieda',
    'true,,Cisco Webex Extension,jlhmfgmfgeifomenelglieieghnjghma',
    'true,,Clear Cache,cppjkneekbjaeellbfkmgnhonkkjfpdn',
    'true,,ClickUp: Tasks, Screenshots, Email, Time,pliibjocnfmkagafnbkfcimonlnlpghj',
    'true,,Clockify Time Tracker,pmjeegjhjdlccodhacdgbgfagbpmccpe',
    'true,,Cloud Vision,nblmokgbialjjgfhfofbgfcghhbkejac',
    'true,,Cloud9,nbdmccoknlfggadpfkmcpnamfnbkmkcp',
    'true,,ColorPick Eyedropper,ohcpnigalekghcmgcdcenkpelffpdolg',
    'true,,Copper CRM for Gmail,hpfmedbkgaakgagknibnonpkimkibkla',
    'true,,Copper CRM for Gmail™,hpfmedbkgaakgagknibnonpkimkibkla',
    'true,,Crunchbase - B2B Company & Contact Info,mdfjplgeknamfodpoghbmhhlcjoacnbp',
    'true,,DEPRECATED Secure Shell App,pnhechapfaindjhompbnflcldabbghjo',
    'true,,Datanyze Chrome Extension,mlholfadgbpidekmhdibonbjhdmpmafd',
    'true,,DealFinder by VoucherCodes,jhgicjdnnonfaedodemjjinbgcoeiajo',
    'true,,Disconnect,jeoacafpbcihiomhlakheieifhpjdfeo',
    'true,,Distill Web Monitor,inlikjemeeknofckkjolnjbpehgadgge',
    'true,,DuckDuckGo Privacy Essentials,bkdgflcldnnnapblkhphbgpggdiikppg',
    'true,,EditThisCookie,fngmhnnpilhplaeedifhccceomclgfbg',
    'true,,Endpoint Verification,callobklhcbilhphinckomhgkigmfocg',
    'true,,Eno® from Capital One®,clmkdohmabikagpnhjmgacbclihgmdje',
    'true,,Espruino Web IDE,bleoifhkdalbjfbobjackfdifdneehpo',
    'true,,Event Merge for Google Calendar™,idehaflielbgpaokehlhidbjlehlfcep',
    'true,,Extensity,jjmflmamggggndanpgfnpelongoepncg',
    'true,,Facebook Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc',
    'true,,FoxyProxy Basic,dookpfaalaaappcdneeahomimbllocnb',
    'true,,Free Maps Ruler,ejpahoknghmacibohhgleeacndkglgmo',
    'true,,GSConnect,jfnifeihccihocjbfcfhicmmgpjicaec',
    'true,,GitHub Red Alert,kmiekjkmkbhbnlempjkaombjjcfhdnfe',
    'true,,Github Absolute Dates,iepecohjelcmdnahbddleblfphbaheno',
    'true,,Google Analytics Parameter Stripper,jbgedkkfkohoehhkknnmlodlobbhafge',
    'true,,Google Docs Offline,ghbmnnjooekpmoecnnnilnnbdlolhkhi',
    'true,,Google Drive,apdfllckaahabafndbhieahigkjlhalf',
    'true,,Google Hangouts,nckgahadagoaajjgafhacjanaoiihapd',
    'true,,Google Keep - Notes and Lists,hmjkmjkepdijhoojdojkdfohbdgmmhki',
    'true,,Google Keep Chrome Extension,lpcaedmchfhocbbapmcbpinfpgnhiddi',
    'true,,Google Mail Checker,mihcahmgecmbnbcchbopgniflfhgnkff',
    'true,,Google Optimize,bhdplaindhdkiflmbfbciehdccfhegci',
    'true,,Google Play Books,mmimngoggfoobjdlefbcabngfnmieonb',
    'true,,Grammarly: Grammar Checker and AI Writing App,kbfnbcaeplbcioakkpcpgfkobkghlhen',
    'true,,Grammarly: Grammar Checker and Writing App,kbfnbcaeplbcioakkpcpgfkobkghlhen',
    'true,,Gravit Designer,pdagghjnpkeagmlbilmjmclfhjeaapaa',
    'true,,HTTPS Everywhere,gcbommkclmclpchllfjekcdonpmejbdp',
    'true,,Honey: Automatic Coupons & Cash Back,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,Honey: Automatic Coupons & Rewards,bmnlcjabgnpnenekpadlanbbkooimhnj',
    'true,,HubSpot Sales,oiiaigjnkhngdbnoookogelabohpglmd',
    'true,,IBA Opt-out (by Google),gbiekjoijknlhijdjbaadobpkdhmoebb',
    'true,,Instapaper,ldjkgaaoikpmhmkelcgkgacicjfbofhh',
    'true,,JSON Formatter,bcjindcccaagfpapjjmafapmmgkkhgoa',
    'true,,JSON Viewer Pro,eifflpmocdbdmepbjaopkkhbfmdgijcc',
    'true,,Jamstash,jccdpflnecheidefpofmlblgebobbloc',
    'true,,Jitsi Meetings,kglhbbefdnlheedjiejgomgmfplipfeb',
    'true,,Link to Text Fragment,pbcodcjpfjdpcineamnnmbkkmkdpajjg',
    'true,,Lolli: Earn Bitcoin When You Shop,fleenceagaplaefnklabikkmocalkcpo',
    'true,,Loom – Free Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Loom – Screen Recorder & Screen Capture,liecbddmkiiihnedobmlmillhodjkdmb',
    'true,,Lucidchart Diagrams,apboafhkiegglekeafbckfjldecefkhn',
    'true,,Markdown Preview Plus,febilkbfcbhebfnokafefeacimjdckgl',
    'true,,Meta Pixel Helper,fdgfkebogiimcoedlicjlajpkdmockpc',
    'true,,NoScript,doojmbjmlfjjnbmnoijecmcbfeoakpjm',
    'true,,Notion Web Clipper,knheggckgoiihginacbkhaalnibhilkk',
    'true,,Office - Enable Copy and Paste,ifbmcpbgkhlpfcodhjhdbllhiaomkdej',
    'true,,Office Editing for Docs, Sheets & Slides,gbkeegbaiigmenfmjfclcdgdpimamgkj',
    'true,,Okta Browser Plugin,glnpjglilkicbckjpbgcfkogebgllemb',
    'true,,OneLogin for Google Chrome,ioalpmibngobedobkmbhgmadaphocjdn',
    'true,,OneTab,chphlpgkkbolifaimnlloiipkdnihall',
    'true,,Outbrain Pixel Tracker,daebadnaphbiobojnpgcenlkgpihmbdc',
    'true,,Outreach Everywhere,chmpifjjfpeodjljjadlobceoiflhdid',
    'true,,Page Analytics (by Google),fnbdnhhicmebfgdgglcdacdapkcihcoh',
    'true,,Password Alert,noondiphcddnnabmjcihcjfbhfklnnep',
    'true,,Picture-in-Picture Extension (by Google),hkgfoiooedgoejojocmhlaklaeopbecg',
    'true,,PlayTo for Chromecast™,jngkenaoceimiimeokpdbmejeonaaami',
    'true,,Playback Rate,jgmkoefgnppfpagkhifpialkkkgnfgag',
    'true,,Postman,fhbjgbiflinjbdggehcddcbncdddomop',
    'true,,Privacy Badger,pkehgijcmpdhfbdbbnkijodmdjhbjlgp',
    'true,,Private Internet Access,jplnlifepflhkbkgonidnobkakhmpnmh',
    'true,,QuillBot for Chrome,iidnbdjijdkbmajdffnidomddglmieko',
    'true,,RSS Subscription Extension (by Google),nlbjncdgjeocebhnmkbbbdekmmmcbfjd',
    'true,,React Developer Tools,fmkadmapgofadopljbjfkapdkoienihi',
    'true,,Reader Mode,llimhhconnjiflfimocjggfjdlmlhblm',
    'true,,Readwise Highlighter,jjhefcfhmnkfeepcpnilbbkaadhngkbi',
    'true,,Refined GitHub,hlepfoohegkhhmjieoechaddaejaokhf',
    'true,,RetailMeNot Deal Finder™️,jjfblogammkiefalfpafidabbnamoknm',
    'true,,SSH for Google Cloud Platform,ojilllmhjhibplnppnamldakhpmdnibd',
    'true,,Save to Google Drive,gmbmikajjgmnabiglmofipeabaddhgne',
    'true,,Save to Pocket,niloccemoadcdkdjlinkgdfekeahmflj',
    'true,,Scraper,poegfpiagjgnenagjphgdklmgcpjaofi',
    'true,,Secure Shell,iodihamcpbpeioajjeobimgagajmlibd',
    'true,,Selenium IDE,mooikfkahbdckldjjndioackbalphokd',
    'true,,Send from Gmail (by Google),pgphcomnlaojlmmcjmiddhdapjpbgeoc',
    'true,,Send to Kindle for Google Chrome™,cgdjpilhipecahhcilnafpblkieebhea',
    'true,,Sendspark Video and Screen Recorder,blimjkpadkhcpmkeboeknjcmiaogbkph',
    'true,,Session Buddy,edacconmaakjimmfgnblocblbcdcpbko',
    'true,,Set Character Encoding,bpojelgakakmcfmjfilgdlmhefphglae',
    'true,,Shodan,jjalcfnidlmpjhdfepjhjbhnhkbgleap',
    'true,,Simple Tab Sorter,cgfpgnepljlgenjclbekbjdlgcodfmjp',
    'true,,Skype Calling,blakpkgjpemejpbmfiglncklihnhjkij',
    'true,,Slack,jeogkiiogjbmhklcnbgkdcjoioegiknm',
    'true,,Super Dark Mode,nlgphodeccebbcnkgmokeegopgpnjfkc',
    'true,,Superhuman,dcgcnpooblobhncpnddnhoendgbnglpn',
    'true,,Tab Wrangler,egnjhciaieeiiohknchakcodbpgjnchh',
    'true,,Tabli,igeehkedfibbnhbfponhjjplpkeomghi',
    'true,,Tag Assistant Legacy (by Google),kejbdjndbnbjgmefkgdddjlbokphdefk',
    'true,,Tampermonkey BETA,gcalenpjmijncebpfijmoaglllgpjagf',
    'true,,TickTick - Todo & Task List,diankknpkndanachmlckaikddgcehkod',
    'true,,Todoist for Chrome,jldhpllghnbhlbpcmnajkpdmadaolakh',
    'true,,UET Tag Helper (by Microsoft Advertising),naijndjklgmffmpembnkfbcjbognokbf',
    'true,,Ubiquiti Device Discovery Tool,hmpigflbjeapnknladcfphgkemopofig',
    'true,,Universal Video Downloader,cogmkaeijeflocngklepoknelfjpdjng',
    'true,,User-Agent Switcher for Chrome,djflhoibgkdhkhhcedjiklpkjnoahfmg',
    'true,,Utime,kpcibgnngaaabebmcabmkocdokepdaki',
    'true,,VidyoWebConnector,mmedphfiemffkinodeemalghecnicmnh',
    'true,,Vimcal,akopimcimmdmklcmegcflfidpfegngke',
    'true,,Vimium,dbepggeogbaibhgnhhndojpepiihcmeb',
    'true,,Vue.js devtools,nhdogjmejiglipccpnnnanhbledajbpd',
    'true,,WAVE Evaluation Tool,jbbplnpkjmmeebjpijfedlgcdilocofh',
    'true,,Wikiwand: Wikipedia Modernized,emffkefkbkpkgpdeeooapgaicgmcbolj',
    'true,,Windscribe - Free Proxy and Ad Blocker,hnmpcagpplmpfojmgmnngilcnanddlhb',
    'true,,Wisdolia,ciknpklcipibmfbgjmdmfdfalklfdlne',
    'true,,WiseStamp email signature,pbcgnkmbeodkmiijjfnliicelkjfcldg',
    'true,,Yesware Sales Engagement,gkjnkapjmjfpipfcccnjbjcbgdnahpjp',
    'true,,Zoom Scheduler,kgjfgplpablkjnlkjmjdecgdpfankdle',
    'true,,Zoom,hmbjbjdpkobdjplfobhljndfdfdipjhg',
    'true,,ZoomInfo Engage Chrome Extension,mnbjlpbmllanehlpbgilmbjgocpmcijp',
    'true,,axe DevTools - Web Accessibility Testing,lhdoppojpmngadmnindnejefpokejbdd',
    'true,,coLaboratory Notebook,pianggobfjcgeihlmfhfgkfalopndooo',
    'true,,crouton integration,gcpneefbbnfalgjniomfjknbcgkbijom',
    'true,,iCloud Bookmarks,fkepacicchenbjecpbpbclokcabebhah',
    'true,,Todoist for Gmail,clgenfnodoocmhnlnpknojdbjjnmecff',
    'true,,Cisco Umbrella Chromebook client (Ext),jcdhmojfecjfmbdpchihbeilohgnbdci',
    'true,,uBlock,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,,writeGPT - ChatGPT Prompt Engineer Assistant,dflcdbibjghipieemcligeelbmackgco',
    'true,Adaware,Safe Torrent Scanner,aegnopegbbhjeeiganiajffnalhlkkjb',
    'true,Adblock, Inc.,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom',
    'true,Adguard Software Ltd,AdGuard AdBlocker,bgnkhhnnamicmpeenaelnjfhikgbkllg',
    'true,AgileBits,1Password extension (desktop app required),aomjjhallfgjeglblehebfpbcfeobpgk',
    'true,AgileBits,1Password – Password Manager,aeblfdkhhhdcdjpifhhbdiojplfjncoa',
    'true,Alexander Shutau,Dark Reader,eimadpbcbfnmbkopoojfekhnkhdbieeh',
    'true,All uBlock contributors,uBlock - free ad blocker,epcnnfbjfcgphgdmggkamkmgojdagdnn',
    'true,Benjamin Hollis,JSONView,gmegofmjomhknnokphhckolhcffdaihd',
    'true,BetaFish,AdBlock — best ad blocker,gighmmpiobklfepjocnamgkkbiglidom',
    'true,Bitwarden Inc.,Bitwarden - Free Password Manager,nngceckbapebfimnlniiiahkandclblb',
    'true,CAD Team,Cookie AutoDelete,fhcgjolkccmbidfldomjliifgaodjagh',
    'true,Clockwise Inc.,Clockwise: AI Calendar & Scheduling Assistant,hjcneejoopafkkibfbcaeoldpjjiamog',
    'true,Clockwise Inc.,Clockwise: Team Time & Calendar Management,hjcneejoopafkkibfbcaeoldpjjiamog',
    'true,Crowdcast, Inc.,Crowdcast Screensharing,kgmadhplahebfoiijgloflhakfjlkbpb',
    'true,Evernote,Evernote Web Clipper,pioclpoplcdbaefihamjohnefbikjilc',
    'true,ExpressVPN,ExpressVPN: VPN proxy for a better internet,fgddmllnllkalaagkghckoinaemmogpe',
    'true,Federico Brigante,GitHub Issue Link Status,nbiddhncecgemgccalnoanpnenalmkic',
    'true,Ghostery,Ghostery – Privacy Ad Blocker,mlomiejdfkolichcflejclcbmpeaniij',
    'true,Guilherme Nascimento,Prevent Duplicate Tabs,eednccpckdkpojaiemedoejdngappaag',
    'true,James Anderson,LeechBlock NG,blaaajhemilngeeffpbfkdjjoefldkok',
    'true,Kas Elvirov,GitHub Gloc,kaodcnpebhdbpaeeemkiobcokcnegdki',
    'true,Keepa GmbH,Keepa - Amazon Price Tracker,neebplgakaahbhdphmkckjjcegoiijjo',
    'true,LastPass,LastPass: Free Password Manager,hdokiejnpimakedhajhdlcegeplioahd',
    'true,Leadjet,Leadjet - Make your CRM work on LinkedIn,kojhcdejfimplnokhhhekhiapceggamn',
    'true,Marker.io,Marker.io: Visual bug reporting for websites,jofhoojcehdmaiibilpcoofpdbbddkkl',
    'true,Microsoft Corporation,Microsoft 365,ndjpnladcallmjemlbaebfadecfhkepb',
    'true,NortonLifeLock Inc,Norton Safe Web,fnpbeacklnhmkkilekogeiekaglbmmka',
    'true,Opera Norway AS,Opera AI Prompts,mljbnbeedpkgakdchcmfapkjhfcogaoc',
    'true,Opera Software AS,Rich Hints Agent,enegjkbbakeegngfapepobipndnebkdk',
    'true,Opera,Cashback Assistant,ompjkhnkeoicimmaehlcmgmpghobbjoj',
    'true,Pawel Psztyc,Advanced REST client,hgmloofddffdnphfgcellkdfbfbjeloo',
    'true,Pushbullet,Pushbullet,chlffgpmiacpedhhbkiomidkjlcfhogd',
    'true,Rakuten,Rakuten: Get Cash Back For Shopping,chhjbpecpncaggjpdakmflnfcopglcmi',
    'true,Raymond Hill & contributors,uBlock Origin,cjpalhdlnbpafiamejdnhcphjbkeiagm',
    'true,Reddit Enhancement Suite contributors,Reddit Enhancement Suite,kbmfpngjjgdllneeigpgjifpgocmfgmb',
    'true,Team Octotree,Octotree - GitHub code tree,bkhaagjahfmjljalopjnoealnfndnagc',
    'true,Thomas Rientjes,Decentraleyes,ldpochfccmkkmhdbclfhpagapcfdljkj',
    'true,Tomas Popela, tpopela@redhat.com,Fedora User Agent,hojggiaghnldpcknpbciehjcaoafceil',
    'true,Tulio Ornelas <ornelas.tulio@gmail.com>,JSON Viewer,gbmdgpbipfallnflgajpaliibnhdgobh',
    'true,Vimeo,Vimeo Record - Screen & Webcam Recorder,ejfmffkmeigkphomnpabpdabfddeadcb',
    'true,Wappalyzer,Wappalyzer - Technology profiler,gppongmhjkpfnbhagpmjfkannfbllamg',
    'true,Yuri Konotopov <ykonotopov@gnome.org>,GNOME Shell integration,gphhapmejobijbbhgpjhcjognlahblep',
    'true,chromeos-recovery-tool-admin@google.com,Chromebook Recovery Utility,jndclpdbaamdhonoechobihbbiimdgai',
    'true,eyeo GmbH,Adblock Plus - free ad blocker,cfhdojbkjhnklbpkdaibdccddilifddb',
    'true,https://metamask.io,MetaMask,nkbihfbeogaeaoehlefnkodbefgpgknn',
    'true,stefanXO,Tab Manager Plus for Chrome,cnkdjjdmfiffagllbiiilooaoofcoeff'
  )
  AND NOT (
    exception_key = 'false,AgileBits,1Password – Password Manager,dppgmdbiimibapkepcbdbmkaabgiofem'
    AND chrome_extensions.path LIKE '%/Microsoft Edge/%'
  )
GROUP BY
  exception_key
