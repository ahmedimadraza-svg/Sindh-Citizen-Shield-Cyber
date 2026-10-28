export interface UrlAnalysisResult {
  url: string;
  riskLevel: 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE' | 'UNKNOWN';
  riskLabel: string;
  threatScore: number; // 0 to 100
  threatIndicators: string[];
  recommendedAction: string;
  isOfficialGov: boolean;
  domain: string;
  protocol: string;
}

export interface ScreenshotAnalysisResult {
  sender?: string;
  matchedKeywords: string[];
  riskAssessment: 'HIGH RISK FRAUD ATTEMPT' | 'SUSPICIOUS ACTIVITY' | 'VERIFIED CIVIC NOTICE' | 'SAFE' | 'UNABLE TO VERIFY';
  riskBadge: 'HIGH RISK' | 'SUSPICIOUS' | 'VERIFIED' | 'LOW RISK' | 'UNKNOWN';
  detectedThreatIndicators: string[];
  defensiveSteps: string[];
  emergencyContactNeeded: boolean;
}

const OFFICIAL_GOV_ROOTS = [
  'gov.pk',
  'gos.pk',
  'bisp.gov.pk',
  'pass.gov.pk',
  'sindh.gov.pk',
  'fia.gov.pk',
  'nccia.gov.pk',
  'pta.gov.pk',
  'nadra.gov.pk',
  'secp.gov.pk',
  'pakistan.gov.pk',
  'cplc.org.pk',
];

const SUSPICIOUS_TLDS = [
  '.xyz',
  '.top',
  '.click',
  '.club',
  '.buzz',
  '.live',
  '.rest',
  '.gq',
  '.ml',
  '.cf',
  '.tk',
  '.ga',
  '.work',
  '.fit',
  '.cn',
];

const WELFARE_KEYWORDS = [
  'bisp',
  'ehsaas',
  'benazir',
  'rashan',
  'welfare',
  '8171',
  '8070',
  'wazaif',
  'kafalat',
  'taleemi',
];

const FINANCIAL_KEYWORDS = [
  'jazzcash',
  'easypaisa',
  'hbl',
  'ubl',
  'meezan',
  'bank',
  'wallet',
  'pin',
  'otp',
];

export function analyzeUrl(rawUrl: string): UrlAnalysisResult {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return {
      url: '',
      riskLevel: 'UNKNOWN',
      riskLabel: 'No URL Provided',
      threatScore: 0,
      threatIndicators: ['Please enter or paste a valid link to inspect.'],
      recommendedAction: 'Input a suspicious web link above to run real-time diagnostics.',
      isOfficialGov: false,
      domain: '',
      protocol: '',
    };
  }

  let formatted = trimmed;
  if (!/^https?:\/\//i.test(formatted)) {
    formatted = 'http://' + formatted;
  }

  let domain = '';
  let protocol = 'http:';
  let pathname = '';
  try {
    const parsed = new URL(formatted);
    domain = parsed.hostname.toLowerCase();
    protocol = parsed.protocol.toLowerCase();
    pathname = parsed.pathname.toLowerCase();
  } catch {
    domain = trimmed.toLowerCase();
  }

  const indicators: string[] = [];
  let threatScore = 0;

  // 1. Strict Hostname Registered-Domain Boundary Check
  // An official government domain MUST end with .gov.pk or .gos.pk as the root zone
  const isDirectGov = OFFICIAL_GOV_ROOTS.some(
    (root) => domain === root || domain.endsWith('.' + root)
  );

  // Check for Look-alike domain deception: e.g. "fia.gov.pk.example.com" or "bisp.gov.pk.fake.xyz"
  const hasLookalikeGovSubdomain =
    !isDirectGov &&
    (domain.includes('fia.gov.pk') ||
      domain.includes('bisp.gov.pk') ||
      domain.includes('pta.gov.pk') ||
      domain.includes('nadra.gov.pk') ||
      domain.includes('sindh.gov.pk') ||
      domain.includes('fia-gov-pk') ||
      domain.includes('bisp-gov-pk'));

  if (hasLookalikeGovSubdomain) {
    return {
      url: trimmed,
      riskLevel: 'MALICIOUS',
      riskLabel: 'DECEPTIVE LOOK-ALIKE GOVERNMENT DOMAIN',
      threatScore: 90,
      threatIndicators: [
        `High-risk look-alike domain: Hostname '${domain}' spoofed official government naming on an unauthenticated third-party host.`,
        'Registered root domain is NOT an official Pakistani government gateway (.gov.pk).',
        'Commonly deployed in credential harvesting and identity theft campaigns.',
      ],
      recommendedAction: 'Do NOT open this link or disclose credentials. The authentic portal is strictly https://fia.gov.pk or https://bisp.gov.pk.',
      isOfficialGov: false,
      domain,
      protocol,
    };
  }

  // Pathname-only reference on unrelated domain (e.g. "https://example.com/fia.gov.pk")
  const isPathOnlyGov = !isDirectGov && (pathname.includes('fia.gov.pk') || pathname.includes('bisp.gov.pk'));
  if (isPathOnlyGov) {
    indicators.push(`Domain '${domain}' is an unrelated third party; the path merely references a government keyword.`);
  }

  if (isDirectGov) {
    return {
      url: trimmed,
      riskLevel: 'SAFE',
      riskLabel: 'AUTHENTICATED OFFICIAL PORTAL',
      threatScore: 0,
      threatIndicators: [
        'Domain verified under Government of Pakistan / Sindh federal registry (.gov.pk / .gos.pk).',
        'Official public sector organization gateway.',
      ],
      recommendedAction: 'Legitimate official gateway. Ensure your browser connection uses HTTPS.',
      isOfficialGov: true,
      domain,
      protocol,
    };
  }

  // 2. Suspicious TLD check
  const hasSuspiciousTld = SUSPICIOUS_TLDS.some((tld) => domain.endsWith(tld));
  if (hasSuspiciousTld) {
    threatScore += 35;
    indicators.push('Suspicious top-level domain (.xyz / .top / .click) commonly used in credential harvesting.');
  }

  // 3. Welfare impersonation check directly on hostname
  // NOTE: Only check hostname to avoid false positives on legitimate news/encyclopedia articles (e.g. wikipedia.org/wiki/BISP)
  const isInformationalSite = domain.endsWith('wikipedia.org') || domain.endsWith('dawn.com') || domain.endsWith('tribune.com.pk') || domain.endsWith('bbc.com');
  const matchesWelfare = !isInformationalSite && WELFARE_KEYWORDS.some((kw) => domain.includes(kw));
  if (matchesWelfare) {
    threatScore += 40;
    indicators.push('Misleading brand name impersonating official financial welfare program.');
  }

  // 4. Protocol check
  if (protocol === 'http:') {
    threatScore += 25;
    indicators.push('Absence of encrypted HTTPS transport; credentials entered can be intercepted.');
  }

  // 5. Bank/Wallet impersonation check on hostname
  const matchesFin = !isInformationalSite && FINANCIAL_KEYWORDS.some((kw) => domain.includes(kw));
  if (matchesFin) {
    threatScore += 35;
    indicators.push('Deceptive domain spoofing mobile wallet or banking gateway (JazzCash / Easypaisa).');
  }

  // 6. Hyphenated brand decoy count
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    threatScore += 20;
    indicators.push('High-risk domain obfuscation detected with multiple hyphenated brand decoys.');
  }

  // 7. Free hosting / staging subdomains
  if (domain.includes('firebaseapp.com') || domain.includes('000webhost') || domain.includes('ngrok') || domain.includes('pages.dev')) {
    threatScore += 25;
    indicators.push('Hosted on free temporary staging infrastructure frequently abused by scammers.');
  }

  if (threatScore >= 50) {
    return {
      url: trimmed,
      riskLevel: 'MALICIOUS',
      riskLabel: 'HIGH-RISK FRAUD LINK DETECTED',
      threatScore: Math.min(100, threatScore),
      threatIndicators: indicators,
      recommendedAction: 'Do NOT Click or Enter PIN',
      isOfficialGov: false,
      domain,
      protocol,
    };
  } else if (threatScore > 0) {
    return {
      url: trimmed,
      riskLevel: 'SUSPICIOUS',
      riskLabel: 'SUSPICIOUS LINK - EXERCISE CAUTION',
      threatScore,
      threatIndicators: indicators,
      recommendedAction: 'Exercise caution. Do not submit CNIC, password, or bank information on unverified sites.',
      isOfficialGov: false,
      domain,
      protocol,
    };
  }

  return {
    url: trimmed,
    riskLevel: 'UNKNOWN',
    riskLabel: 'UNVERIFIED DOMAIN',
    threatScore: 0,
    threatIndicators: [
      'This domain is not in the Pakistani government registry, but no explicit malice signatures were detected.',
      'Exercise standard caution before entering personal or financial details.',
    ],
    recommendedAction: 'Practice standard cyber hygiene. Verify official channels directly.',
    isOfficialGov: false,
    domain,
    protocol,
  };
}

export function analyzeScreenshotText(
  rawText: string,
  metadata?: { sender?: string }
): ScreenshotAnalysisResult {
  const trimmed = rawText.trim();
  if (!trimmed) {
    return {
      sender: metadata?.sender,
      matchedKeywords: [],
      riskAssessment: 'UNABLE TO VERIFY',
      riskBadge: 'UNKNOWN',
      detectedThreatIndicators: ['Screenshot text is empty or unreadable.'],
      defensiveSteps: ['Upload a clearer, higher-resolution capture of the message or notice.'],
      emergencyContactNeeded: false,
    };
  }

  const text = trimmed.toLowerCase();
  const sender = metadata?.sender || '';
  const indicators: string[] = [];
  const matchedKeywords: string[] = [];

  // -------------------------------------------------------------
  // CRITICAL CATEGORY R: GENUINE PUBLIC SAFETY ADVISORY CHECK
  // A warning ABOUT a scam is NOT a scam!
  // -------------------------------------------------------------
  const isProtectiveWarning =
    /never\s+(share|provide|disclose|give|tell)\b.*(otp|pin|password|mpin|code)/i.test(text) ||
    /do\s+not\s+(share|provide|disclose|give|tell)\b.*(otp|pin|password|mpin|code)/i.test(text) ||
    /never\s+ask\s+for\b.*(otp|pin|password)/i.test(text) ||
    /caution\s+against\b.*(fraud|scam|scheme)/i.test(text) ||
    /(public\s+advisory|cyber\s+advisory|security\s+alert)\b/i.test(text);

  const containsVerifiedGovernmentChannels =
    text.includes('1991') ||
    text.includes('complaint.fia.gov.pk') ||
    text.includes('8171') ||
    text.includes('cnic.sims.pk') ||
    text.includes('0800-55055') ||
    sender === '668' ||
    sender === '8171';

  // Check if active scam demands exist
  const hasActiveScamDemand =
    /call\s+(\d|03\d{2})[^\.\n]*to\s+claim/i.test(text) ||
    /share\s+otp\s+to\s+claim/i.test(text) ||
    /tell\s+your\s+(pin|otp|mpin)/i.test(text) ||
    /send\s+ransom/i.test(text) ||
    /transfer\s+fee\s+to\s+claim/i.test(text);

  if (isProtectiveWarning && containsVerifiedGovernmentChannels && !hasActiveScamDemand) {
    return {
      sender,
      matchedKeywords: ['public advisory', 'anti-fraud warning', 'protective guidance'],
      riskAssessment: 'VERIFIED CIVIC NOTICE',
      riskBadge: 'VERIFIED',
      detectedThreatIndicators: [
        'Genuine public safety notice educating citizens against digital fraud and credential theft.',
        'Actively warns against disclosing sensitive PINs or OTPs (protective advice).',
        'Contains authenticated official reporting channels (Helpline 1991 / BISP 8171 / PTA).',
      ],
      defensiveSteps: [
        'Observe the cyber safety guidelines described in the notice.',
        'Never disclose your OTP, PIN, or banking passwords over phone or SMS.',
        'Official reports can be submitted at complaint.fia.gov.pk or via Helpline 1991.',
      ],
      emergencyContactNeeded: false,
    };
  }

  // Routine PTA SIM count check from shortcode 668
  if ((sender === '668' || text.includes('cnic.sims.pk') || text.includes('total active sims')) && !hasActiveScamDemand) {
    return {
      sender,
      matchedKeywords: ['sim verification', 'pta 668'],
      riskAssessment: 'SAFE',
      riskBadge: 'LOW RISK',
      detectedThreatIndicators: [
        'Standard informational format consistent with PTA SIM count notifications from shortcode 668.',
        'No demands for financial payment, OTPs, or credential submission.',
      ],
      defensiveSteps: [
        'If you requested this verification, the notification is routine.',
        'If you suspect unauthorized SIMs, visit cnic.sims.pk or your cellular customer center with your CNIC.',
      ],
      emergencyContactNeeded: false,
    };
  }

  let threatScore = 0;

  // 1. Advance fee / Prize grant patterns
  const prizePatterns = [
    { key: '25,000 cash grant', label: "Advance fee & lottery prize keywords matched ('25,000 cash grant')" },
    { key: '25000', label: "Monetary inducement keywords matched ('25000 grant / cash')" },
    { key: 'won', label: "Unsolicited lottery winnings claim matched" },
    { key: 'inam', label: "Prize/inam lottery lure identified" },
    { key: 'bisp prize', label: "Impersonation of Benazir Income Support Program" },
    { key: 'approved for', label: "Fabricated official approval claim" },
  ];

  for (const pattern of prizePatterns) {
    if (text.includes(pattern.key)) {
      matchedKeywords.push(pattern.key);
      if (!indicators.includes(pattern.label)) {
        indicators.push(pattern.label);
      }
      threatScore += 25;
    }
  }

  // 2. Private 11-digit sender check
  const isPrivateSim = sender.startsWith('+92 3') || sender.startsWith('03') || /03\d{2}[-\s]?\d{7}/.test(text);
  const mentionsWelfare = text.includes('bisp') || text.includes('ehsaas') || text.includes('grant') || text.includes('8171');

  if (isPrivateSim && mentionsWelfare) {
    threatScore += 35;
    indicators.push('Impersonating official government welfare program from a private 11-digit SIM.');
  }

  // 3. Credential & OTP harvesting (Active demands)
  const isDemandingOtp =
    /share\s+(otp|pin|code)/i.test(text) ||
    /tell\s+(pin|otp)/i.test(text) ||
    /provide\s+(otp|pin)/i.test(text) ||
    /batayein\b.*(pin|otp)/i.test(text) ||
    (text.includes('otp') && text.includes('call')) ||
    (text.includes('pin') && text.includes('call'));

  if (isDemandingOtp) {
    threatScore += 40;
    indicators.push('Credential harvesting: solicitation of one-time password (OTP) or mobile wallet PIN.');
  }

  // 4. Blackmail / Extortion
  if (
    text.includes('ransom') ||
    text.includes('broadcast') ||
    text.includes('private recording') ||
    text.includes('recording will be') ||
    text.includes('video call manipulation') ||
    text.includes('blackmail') ||
    text.includes('extortion')
  ) {
    threatScore += 50;
    indicators.push('Coercive digital extortion or non-consensual media blackmail threat detected.');
  }

  // 5. Account deactivation threats
  if (text.includes('deactivation') || text.includes('scheduled for deactivation') || text.includes('blocked in 24 hours')) {
    threatScore += 30;
    indicators.push('Urgency manipulation: false warning of imminent account termination or debit card block.');
  }

  // 6. Suspicious link on delivery or payment
  if (text.includes('.click') || text.includes('.xyz') || text.includes('.top') || (text.includes('parcel') && text.includes('http'))) {
    threatScore += 35;
    indicators.push('Suspicious delivery smishing or unverified tracking URL detected.');
  }

  if (threatScore >= 45) {
    return {
      sender,
      matchedKeywords,
      riskAssessment: 'HIGH RISK FRAUD ATTEMPT',
      riskBadge: 'HIGH RISK',
      detectedThreatIndicators: indicators,
      defensiveSteps: [
        'Do NOT call back the sender or transfer any advance registration fee.',
        'Never disclose your PIN or SMS confirmation code.',
        'Forward this fraudulent SMS to PTA at shortcode 9000 and report to FIA Helpline: 1991.',
      ],
      emergencyContactNeeded: true,
    };
  } else if (threatScore > 15) {
    return {
      sender,
      matchedKeywords,
      riskAssessment: 'SUSPICIOUS ACTIVITY',
      riskBadge: 'SUSPICIOUS',
      detectedThreatIndicators: indicators,
      defensiveSteps: [
        'Verify independently by visiting the official website or physical branch.',
        'Do not click embedded links or call numbers provided in the message.',
      ],
      emergencyContactNeeded: false,
    };
  }

  return {
    sender,
    matchedKeywords,
    riskAssessment: 'SAFE',
    riskBadge: 'LOW RISK',
    detectedThreatIndicators: ['No common fraud, impersonation, or extortion signatures detected in this excerpt.'],
    defensiveSteps: ['Continue to practice safe cyber hygiene and never share your banking OTP.'],
    emergencyContactNeeded: false,
  };
}
