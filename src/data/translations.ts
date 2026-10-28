export type SupportedLanguage = 'en' | 'sd' | 'ur';

export interface Translations {
  appName: string;
  officialSubtitle: string;
  emergencyDial: string;
  heroTag: string;
  heroDefenseLink: string;
  heroTitle: string;
  heroSubtitle: string;

  // Prominent Actions Switcher
  actionCheckLink: string;
  actionCheckLinkDesc: string;
  actionCheckScreenshot: string;
  actionCheckScreenshotDesc: string;
  activeTabBoth: string;

  // Link Inspector
  linkInspectorTitle: string;
  linkInspectorSubtitle: string;
  liveEngineBadge: string;
  linkPlaceholder: string;
  pasteBtn: string;
  sampleLabel: string;
  sampleBisp: string;
  sampleGov: string;
  sampleJazz: string;
  sampleWhatsapp: string;
  inspectBtn: string;
  actionRecommended: string;

  // Screenshot analyzer
  screenshotTitle: string;
  screenshotSubtitle: string;
  readyForAnalysis: string;
  analyzeScreenshotBtn: string;
  localFirstNotice: string;
  riskAssessmentTitle: string;
  detectedThreatIndicatorsTitle: string;
  immediateDefensiveStepsTitle: string;
  choosePresetSample: string;
  uploadCustom: string;

  // Helpline
  emergencyHelplineLabel: string;
  emergencyHelplineTitle: string;
  emergencyHelplineSubtitle: string;
  emergencyDialCode: string;

  // Threat Feed
  threatFeedTitle: string;
  threatFeedBadge: string;
  threatFeedViewAll: string;

  // Cyber hygiene
  hygieneRulesTitle: string;
  hygieneRule1Title: string;
  hygieneRule1Desc: string;
  hygieneRule2Title: string;
  hygieneRule2Desc: string;
  hygieneRule3Title: string;
  hygieneRule3Desc: string;

  // Navigation
  navCheckLink: string;
  navAnalyzeImage: string;
  navFia1991: string;
  navScamAlerts: string;

  // Dialogs
  emergencyModalTitle: string;
  emergencyModalDesc: string;
  emergencyStep1: string;
  emergencyStep2: string;
  emergencyStep3: string;
  dialNowBtn: string;
  closeBtn: string;
}

export const translations: Record<SupportedLanguage, Translations> = {
  en: {
    appName: 'Sindh Cyber Saathi',
    officialSubtitle: 'Civic Cyber Defense Platform',
    emergencyDial: 'FIA 1991',
    heroTag: 'SINDH YOUTH INNOVATION CHALLENGE',
    heroDefenseLink: 'FIA Cybercrime Defense',
    heroTitle: 'Evidence-Based Cyber Defense for Citizens of Sindh',
    heroSubtitle:
      'Inspect deceptive welfare links, analyze suspicious screenshots, and verify digital claims with transparent, verifiable evidence.',

    actionCheckLink: 'Check a Link',
    actionCheckLinkDesc: 'Inspect URLs, verify official domains (.gov.pk / .gos.pk), and detect phishing threats before you click.',
    actionCheckScreenshot: 'Check a Screenshot',
    actionCheckScreenshotDesc: 'Upload SMS alerts, WhatsApp messages, payment slips, or official notices to analyze evidence.',
    activeTabBoth: 'View Both Tools',

    linkInspectorTitle: 'Instant Link Inspector',
    linkInspectorSubtitle: 'Analyze protocols, domain reputation, and deceptive redirection',
    liveEngineBadge: 'LIVE ENGINE',
    linkPlaceholder: 'http://bisp-welfare-cash.claim-now.xyz',
    pasteBtn: 'Paste',
    sampleLabel: 'Test with sample:',
    sampleBisp: 'Fake BISP Scam URL',
    sampleGov: 'Official Gov Portal',
    sampleJazz: 'Fake JazzCash Alert',
    sampleWhatsapp: 'WhatsApp 50GB Gift',
    inspectBtn: 'Inspect Link Diagnostics',
    actionRecommended: 'Action Recommended:',

    screenshotTitle: 'Analyze a Suspicious Screenshot',
    screenshotSubtitle: 'Detect extortion threats, fake bank notices & lottery SMS',
    readyForAnalysis: 'Ready for analysis',
    analyzeScreenshotBtn: 'Analyze Screenshot',
    localFirstNotice: 'Local-first analysis. Uploads are processed in your browser and not retained on servers.',
    riskAssessmentTitle: 'RISK ASSESSMENT',
    detectedThreatIndicatorsTitle: 'Detected Threat Indicators:',
    immediateDefensiveStepsTitle: 'IMMEDIATE DEFENSIVE STEPS:',
    choosePresetSample: 'Switch Preset Scam Case:',
    uploadCustom: 'Upload Your Image',

    emergencyHelplineLabel: '24/7 FEDERAL EMERGENCY HELPLINE',
    emergencyHelplineTitle: 'Blackmail, Extortion, or Unauthorized Transfer?',
    emergencyHelplineSubtitle: 'Call FIA Cybercrime Wing directly for immediate freeze and legal pursuit.',
    emergencyDialCode: '1991',

    threatFeedTitle: 'Common Digital Scams in Sindh',
    threatFeedBadge: 'Threat Feed',
    threatFeedViewAll: 'Filter & Browse Alerts',

    hygieneRulesTitle: 'Essential Citizen Cyber Hygiene Rules',
    hygieneRule1Title: 'Never Share OTP',
    hygieneRule1Desc: 'No agency asks for your SMS code',
    hygieneRule2Title: 'Verify .gov.pk',
    hygieneRule2Desc: 'Legit portals only end in .gov.pk',
    hygieneRule3Title: 'No Advance Fees',
    hygieneRule3Desc: 'Real grants never charge fees to collect',

    navCheckLink: 'Check Link',
    navAnalyzeImage: 'Analyze Image',
    navFia1991: 'FIA 1991',
    navScamAlerts: 'Scam Alerts',

    emergencyModalTitle: 'FIA Cybercrime Emergency Response (1991)',
    emergencyModalDesc: 'Direct line to the Federal Investigation Agency (FIA) National Cyber Crime Reporting Centre.',
    emergencyStep1: 'Call 1991 immediately if money was deducted from your JazzCash, Easypaisa, or bank account within the last 2 hours.',
    emergencyStep2: 'Inform them of recipient account details to trigger an immediate inter-bank freeze via 1Link/SBP.',
    emergencyStep3: 'Preserve all WhatsApp chats, SMS, caller numbers, and transaction IDs as forensic evidence.',
    dialNowBtn: 'Call FIA Helpline 1991',
    closeBtn: 'Close & Return',
  },

  sd: {
    appName: 'سنڌ سائبر ساٿي (Sindh Cyber Saathi)',
    officialSubtitle: 'سرڪاري شهري تحفظ پليٽ فارم',
    emergencyDial: 'FIA 1991',
    heroTag: 'سنڌ يوٿ انوويشن چئلينج',
    heroDefenseLink: 'ايف آءِ اي سائبر بچاءُ لنڪ',
    heroTitle: 'جعلي لنڪس ۽ ڊجيٽل فراڊ کان سنڌ جي شهرين جو بچاءُ',
    heroSubtitle:
      'شڪي لنڪس ۽ اسڪرين شاٽس جي شفاف ۽ ثبوت تي ٻڌل تصديق ذريعي مالي ۽ ڊجيٽل نقصان کان محفوظ رهو.',

    actionCheckLink: 'لنڪ چڪاسيو',
    actionCheckLinkDesc: 'شڪي لنڪن جو تجزيو ڪريو، سرڪاري ڊومينز (.gov.pk / .gos.pk) جي تصديق ڪريو ۽ فراڊ کان بچو.',
    actionCheckScreenshot: 'اسڪرين شاٽ چڪاسيو',
    actionCheckScreenshotDesc: 'ايس ايم ايس، واٽس ايپ پيغامن، رسيدن يا نوٽيسن جا تصويري ثبوت چڪاسيو.',
    activeTabBoth: 'ٻئي ٽولز ڏسو',

    linkInspectorTitle: 'فوري لنڪ انسپيڪٽر',
    linkInspectorSubtitle: 'پروٽوڪول، ڊومين جي ساک ۽ غلط ري-ڊائريڪشن جي چڪاس ڪريو',
    liveEngineBadge: 'لائيو سسٽم',
    linkPlaceholder: 'http://bisp-welfare-cash.claim-now.xyz',
    pasteBtn: 'پيسٽ',
    sampleLabel: 'نموني سان چڪاسيو:',
    sampleBisp: 'جعلي بي آءِ ايس پي فراڊ لنڪ',
    sampleGov: 'سرڪاري حڪومتي پورٽل',
    sampleJazz: 'جعلي جاز ڪيش ميسيج',
    sampleWhatsapp: 'واٽس ايپ انعامي لنڪ',
    inspectBtn: 'لنڪ جي چڪاس ڪريو',
    actionRecommended: 'تجويز ڪيل عمل:',

    screenshotTitle: 'شڪي اسڪرين شاٽ جي چڪاس ڪريو',
    screenshotSubtitle: 'بليڪ ميلنگ، جعلي بينڪ نوٽيس ۽ لاٽري ايس ايم ايس ڳوليو',
    readyForAnalysis: 'تجزئي لاءِ تيار',
    analyzeScreenshotBtn: 'اسڪرين شاٽ چڪاسيو',
    localFirstNotice: 'توهان جي پرائيويسي محفوظ آهي. تصوير توهان جي برائوزر ۾ ئي چڪاسي وڃي ٿي.',
    riskAssessmentTitle: 'خطري جي چڪاس',
    detectedThreatIndicatorsTitle: 'ڳوليل خطري جا نشان:',
    immediateDefensiveStepsTitle: 'فوري بچاءُ جا قدم:',
    choosePresetSample: 'نموني وارا فراڊ ڪيس:',
    uploadCustom: 'پنهنجي تصوير اپلوڊ ڪريو',

    emergencyHelplineLabel: '24/7 وفاقي ايمرجنسي هيلپ لائن',
    emergencyHelplineTitle: 'بليڪ ميلنگ، ڌمڪي، يا پئسن جي ناجائز منتقلي؟',
    emergencyHelplineSubtitle: 'اڪائونٽ فريز ڪرڻ ۽ قانوني ڪارروائي لاءِ سڌو سنئون ايف آءِ اي سائبر ڪرائيم سان رابطو ڪريو.',
    emergencyDialCode: '1991',

    threatFeedTitle: 'سنڌ ۾ عام ڊجيٽل فراڊ',
    threatFeedBadge: 'فراڊ الرٽس',
    threatFeedViewAll: 'سڀ ڏسو',

    hygieneRulesTitle: 'شهري سائبر حفاظت جا 3 سڀ کان اهم اصول',
    hygieneRule1Title: 'ڪڏهن به OTP نه ڏيو',
    hygieneRule1Desc: 'ڪو به سرڪاري ادارو توهان کان پن ڪوڊ نٿو گهري',
    hygieneRule2Title: 'فقط .gov.pk جي تصديق ڪريو',
    hygieneRule2Desc: 'اصل سرڪاري پورٽل صرف .gov.pk تي ختم ٿين ٿا',
    hygieneRule3Title: 'ڪابه اڳواٽ فيس نه ڏيو',
    hygieneRule3Desc: 'حقيقي امداد ملڻ لاءِ ڪڏهن به اڳواٽ فيس ناهي ورتي ويندي',

    navCheckLink: 'لنڪ چڪاسيو',
    navAnalyzeImage: 'تصوير چڪاسيو',
    navFia1991: 'FIA 1991',
    navScamAlerts: 'فراڊ الرٽس',

    emergencyModalTitle: 'ايف آءِ اي سائبر ڪرائيم ايمرجنسي (1991)',
    emergencyModalDesc: 'وفاقي جاچ اداري (FIA) جي سائبر ڪرائيم ونگ سان فوري مدد.',
    emergencyStep1: 'جيڪڏهن جاز ڪيش، ايزي پيسا يا بينڪ مان ناجائز پئسا نڪتا آهن ته ترت 1991 تي ڪال ڪريو.',
    emergencyStep2: 'پئسا وصول ڪندڙ جو اڪائونٽ نمبر ٻڌايو ته جيئن 1Link ذريعي اڪائونٽ فريز ٿي سگهي.',
    emergencyStep3: 'ميسيج، ڪال رڪارڊنگ ۽ واٽس ايپ اسڪرين شاٽس ثبوت طور محفوظ رکو.',
    dialNowBtn: 'ايف آءِ اي 1991 تي ڪال ڪريو',
    closeBtn: 'بند ڪريو',
  },

  ur: {
    appName: 'سندھ سائبر ساتھی (Sindh Cyber Saathi)',
    officialSubtitle: 'سرکاری شہری تحفظ پلیٹ فارم',
    emergencyDial: 'FIA 1991',
    heroTag: 'سندھ یوتھ انوویشن چیلنج',
    heroDefenseLink: 'ایف آئی اے سائبر ڈیفنس لنک',
    heroTitle: 'شہریوں کا ڈیجیٹل فراڈ اور جعلی لنکس سے تحفظ',
    heroSubtitle:
      'مشکوک لنکس اور اسکرین شاٹس کی شفاف، ثبوت پر مبنی جانچ کے ذریعے مالی نقصان اور ہیکنگ سے بچیں۔',

    actionCheckLink: 'لنک چیک کریں',
    actionCheckLinkDesc: 'مشکوک لنکس کا معائنہ کریں، سرکاری ڈومینز (.gov.pk / .gos.pk) کی تصدیق کریں اور محفوظ رہیں۔',
    actionCheckScreenshot: 'اسکرین شاٹ چیک کریں',
    actionCheckScreenshotDesc: 'ایس ایم ایس، واٹس ایپ پیغامات، رسیدوں یا نوٹسز کا فورنزک تصویری جائزہ لیں۔',
    activeTabBoth: 'دونوں ٹولز دیکھیں',

    linkInspectorTitle: 'فوری لنک انسپکٹر',
    linkInspectorSubtitle: 'پروٹوکول، ڈومین کی تصدیق اور غلط ری ڈائریکشن چیک کریں',
    liveEngineBadge: 'لائیو سسٹم',
    linkPlaceholder: 'http://bisp-welfare-cash.claim-now.xyz',
    pasteBtn: 'پیسٹ',
    sampleLabel: 'نمونے سے چیک کریں:',
    sampleBisp: 'جعلی بی آئی ایس پی لنک',
    sampleGov: 'سرکاری حکومتی پورٹل',
    sampleJazz: 'جعلی جاز کیش الرٹ',
    sampleWhatsapp: 'واٹس ایپ 50 جی بی فراڈ',
    inspectBtn: 'لنک کا معائنہ کریں',
    actionRecommended: 'تجویز کردہ حفاظتی اقدام:',

    screenshotTitle: 'مشکوک اسکرین شاٹ چیک کریں',
    screenshotSubtitle: 'بلیک میلنگ، جعلی بینک نوٹس اور لاٹری ایس ایم ایس پکڑیں',
    readyForAnalysis: 'تجزیے کے لیے تیار',
    analyzeScreenshotBtn: 'اسکرین شاٹ کا تجزیہ کریں',
    localFirstNotice: 'مکمل رازداری۔ تصاویر آپ کے براؤزر کے اندر ہی چیک کی جاتی ہیں، سرور پر محفوظ نہیں ہوتیں۔',
    riskAssessmentTitle: 'خطرے کی تشخیص',
    detectedThreatIndicatorsTitle: 'شناخت شدہ خطرات:',
    immediateDefensiveStepsTitle: 'فوری حفاظتی اقدامات:',
    choosePresetSample: 'جعلی پیغامات کے نمونے:',
    uploadCustom: 'اپنی تصویر اپلوڈ کریں',

    emergencyHelplineLabel: '24/7 وفاقی ایمرجنسی ہیلپ لائن',
    emergencyHelplineTitle: 'بلیک میلنگ، ہراسگی یا غیر مجاز رقم کی منتقلی؟',
    emergencyHelplineSubtitle: 'اکاؤنٹ فریز اور قانونی کارروائی کے لیے ایف آئی اے سائبر کرائم ونگ سے فوری رابطہ کریں۔',
    emergencyDialCode: '1991',

    threatFeedTitle: 'سندھ میں عام ڈیجیٹل دھوکے بازیاں',
    threatFeedBadge: 'تھریٹ فیڈ',
    threatFeedViewAll: 'تمام الرٹس دیکھیں',

    hygieneRulesTitle: 'شہری سائبر حفظانِ صحت کے 3 بنیادی اصول',
    hygieneRule1Title: 'کبھی بھی OTP مت بتائیں',
    hygieneRule1Desc: 'کوئی بھی ادارہ آپ سے ایس ایم ایس کوڈ نہیں مانگتا',
    hygieneRule2Title: 'صرف .gov.pk کی تصدیق کریں',
    hygieneRule2Desc: 'اصلی سرکاری پورٹلز ہمیشہ .gov.pk پر ختم ہوتے ہیں',
    hygieneRule3Title: 'کوئی پیشگی فیس نہ دیں',
    hygieneRule3Desc: 'حقیقی امداد کے لیے کبھی بھی ایڈوانس فیس طلب نہیں کی جاتی',

    navCheckLink: 'لنک چیک کریں',
    navAnalyzeImage: 'تصویر چیک کریں',
    navFia1991: 'FIA 1991',
    navScamAlerts: 'اسکیم الرٹس',

    emergencyModalTitle: 'ایف آئی اے سائبر کرائم ایمرجنسی (1991)',
    emergencyModalDesc: 'وفاقی تحقیقاتی ادارے (FIA) نیشنل سائبر کرائم رپورٹنگ سینٹر کی براہ راست لائن۔',
    emergencyStep1: 'اگر جاز کیش، ایزی پیسہ یا بینک سے رقم کٹ گئی ہو تو فوری طور پر 1991 پر کال کریں۔',
    emergencyStep2: 'رقم وصول کرنے والے کا اکاؤنٹ نمبر بتائیں تاکہ ون لنک کے ذریعے فوری اکاؤنٹ فریز کرایا جا سکے۔',
    emergencyStep3: 'تمام ایس ایم ایس، کال ریکارڈنگ اور واٹس ایپ پیغامات کے اسکرین شاٹ محفوظ رکھیں۔',
    dialNowBtn: 'ایف آئی اے 1991 کال کریں',
    closeBtn: 'واپس جائیں',
  },
};
