import type { DecisionPathLog } from './diagnosticLogger.ts';

export type StandardVerdict =
  | 'CONFIRMED THREAT'
  | 'SUSPICIOUS'
  | 'NO KNOWN THREAT FOUND'
  | 'UNABLE TO VERIFY';

export interface QuestionResult {
  answered: boolean;
  summary: string;
  details?: string;
  findings?: string;
}

export interface FiveQuestionsAudit {
  questionA_messageContent: QuestionResult;
  questionB_suspiciousInstructions: QuestionResult;
  questionC_destinationUrl: QuestionResult;
  questionD_officialCorroboration: QuestionResult;
  questionE_senderAuthenticated: QuestionResult;
}

export type RecordAuthenticityStatus =
  | 'RECORD_NOT_INDEPENDENTLY_VERIFIED'
  | 'OFFICIAL_RECORD_VERIFIED'
  | 'CONTRADICTED_BY_OFFICIAL_RECORD'
  | 'NOT_APPLICABLE';

export interface RecordAuthenticityAudit {
  status: RecordAuthenticityStatus;
  label: string;
  summary: string;
  officialVerificationUrl?: string;
  limitations: string;
}

export interface StructuredAuditReport {
  partA_contentAndClaims: {
    summary: string;
    documentType: string;
    extractedReferenceNumbers: string[];
    extractedVehicleDetails?: string;
    extractedAmounts: string[];
    claimedIssuingAuthority?: string;
  };
  partB_suspiciousRequests: {
    hasScamSignals: boolean;
    detectedSignals: string[];
    demandsCredentials: boolean;
    coerciveThreats: boolean;
    unauthorizedPaymentChannel: boolean;
    summary: string;
  };
  partC_urlAndDomainRisks: {
    hasUrl: boolean;
    primaryUrl?: string;
    domain?: string;
    isDeceptiveSubdomain: boolean;
    isTyposquat: boolean;
    isHomograph: boolean;
    isHttpUnencrypted: boolean;
    summary: string;
  };
  partD_officialCorroboration: {
    claimedEntity?: string;
    officialPortal?: string;
    corroborationStatus: 'verified_official' | 'contradicted_impersonation' | 'unverified_private' | 'not_applicable';
    summary: string;
  };
  partE_senderAuthenticity: {
    senderString?: string;
    isCarrierVerified: boolean;
    verdict: string;
    summary: string;
  };
  partF_recordAuthenticity: RecordAuthenticityAudit;
  partG_threatIntelligence: {
    checked: boolean;
    provider: string;
    hasThreatMatch: boolean;
    threatTypes: string[];
    summary: string;
  };
  partH_evidenceQuality: {
    isReadable: boolean;
    confidence: 'high' | 'medium' | 'low' | 'unreadable';
    notes: string;
  };
  partI_serviceLimitations: {
    unavailableChecks: string[];
    limitations: string[];
  };
  partJ_finalVerdict: {
    verdict: StandardVerdict;
    verdictCategory: string;
    statusLabel: string;
    badgeColor: 'red' | 'amber' | 'emerald' | 'slate';
    threatAssessmentSummary: string;
    recordAuthenticitySummary: string;
    actionRecommended: string;
  };
}

export interface EvidenceInput {
  rawText?: string;
  sender?: string;
  urlsExtracted?: string[];
  qrCodeUrl?: string;
  apparentOrg?: string;
  isOfficialGov?: boolean;
  isAuthoritativeEntity?: boolean;
  authoritativeEntityName?: string;
  documentType?: string;
  extractedReferenceNumbers?: string[];
  extractedVehicleDetails?: string;
  extractedAmounts?: string[];
  isChallanOrFine?: boolean;
  isBankOrTransferReceipt?: boolean;
  threatIntelResult?: {
    checked: boolean;
    hasThreatMatch: boolean;
    threatTypes?: string[];
    error?: string;
  };
  destinationPageInfo?: {
    retrieved: boolean;
    httpStatus?: number;
    finalUrl?: string;
    title?: string;
    hasLoginForm?: boolean;
    failureReason?: string;
    requiresJavaScript?: boolean;
  };
  brandImpersonation?: {
    impersonating: boolean;
    claimedOrg?: string;
    officialDomain?: string;
    reason?: string;
  };
  isProtectiveAdvisory?: boolean;
  hasScamDemand?: boolean;
  scamSignals?: string[];
  isUnreadableOrEmpty?: boolean;
  unreadableReason?: string;
  securityBlockReason?: string;
  isShortenedUrl?: boolean;
  isUnverifiedShortLink?: boolean;
  unverifiedShortLinkReason?: string;
  hasUnexpectedGrantClaim?: boolean;
  hasAccountActionViaLink?: boolean;
}

export const SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'cutt.ly',
  'is.gd',
  'rb.gy',
  'buff.ly',
  'ow.ly',
  'shorturl.at',
  'rebrand.ly',
  'bl.ink',
  'tiny.cc',
  'v.gd',
  'qr.ae',
  'rotf.lol',
  'bitly.com',
  's.id',
  'linkr.it',
  't.ly',
]);

export const HIGH_RISK_TLDS = new Set([
  'buzz',
  'top',
  'click',
  'cfd',
  'sbs',
  'rest',
  'surf',
  'monster',
  'cam',
  'skin',
  'icu',
  'uno',
  'work',
  'space',
  'fit',
  'gq',
  'cf',
  'ml',
  'ga',
  'tk',
  'vip',
  'party',
  'quest',
  'beauty',
  'hair',
  'live',
  'loan',
  'xyz',
  'cc',
  'site',
  'online',
  'shop',
  'info',
  'link',
]);

export function hasHighRiskTld(hostOrUrl: string): boolean {
  if (!hostOrUrl) return false;
  try {
    const formatted = hostOrUrl.startsWith('http') ? hostOrUrl : `https://${hostOrUrl}`;
    const host = new URL(formatted).hostname.toLowerCase();
    const parts = host.split('.');
    if (parts.length < 2) return false;
    const tld = parts[parts.length - 1];
    return HIGH_RISK_TLDS.has(tld);
  } catch {
    return false;
  }
}

export const SCAM_URL_KEYWORD_REGEX =
  /(?:free-?recharge|freerecharge|claim-?reward|claim-?bonus|win-?prize|cash-?prize|lucky-?draw|airdrop|giveaway|spin-?wheel|lottery|jackpot|free-?gift|dswd|ayuda|subsidy|bisp|ehsaas|verify-?account|update-?account|unlock-?account|secure-?login|wallet-?connect|claim-?token|mobile-?reward|pak-?records)/i;

export function detectScamUrlLures(urlStr: string): string[] {
  if (!urlStr) return [];
  const signals: string[] = [];
  const lower = urlStr.toLowerCase();

  if (/(?:free-?recharge|freerecharge)/i.test(lower)) {
    signals.push('Deceptive "Free Recharge" incentive lure in link destination.');
  }
  if (/(?:claim-?reward|claim-?bonus|win-?prize|cash-?prize|lucky-?draw|spin-?wheel|lottery|jackpot|free-?gift)/i.test(lower)) {
    signals.push('Deceptive prize, cash reward, or lottery claim lure in link address.');
  }
  if (/(?:airdrop|crypto-?giveaway|wallet-?connect|claim-?token)/i.test(lower)) {
    signals.push('Deceptive cryptocurrency airdrop or wallet authorization lure in web link.');
  }
  if (/(?:dswd|ayuda|social-amelioration|bisp|ehsaas|subsidy|cash-assistance)/i.test(lower)) {
    signals.push('Deceptive civic subsidy or government cash grant lure in web link.');
  }
  if (/(?:verify-?account|update-?account|unlock-?account|secure-?login|login-?verify|kyc-?verify)/i.test(lower)) {
    signals.push('Urgent credential verification or account unlock lure in external web address.');
  }
  if (/(?:pak-?records|community-?records|sim-?verification)/i.test(lower)) {
    signals.push('Unofficial civic database or SIM record verification claim.');
  }
  return signals;
}

export function isShortenedUrl(urlStr: string): boolean {
  if (!urlStr) return false;
  try {
    const formatted = urlStr.startsWith('http') ? urlStr : `https://${urlStr}`;
    const parsed = new URL(formatted);
    const host = parsed.hostname.toLowerCase();
    if (SHORTENER_DOMAINS.has(host) || host.endsWith('.link') || host.endsWith('.short.gy')) {
      return true;
    }
  } catch {
    return /(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|ow\.ly|shorturl\.at|rebrand\.ly|bl\.ink|tiny\.cc|v\.gd|s\.id)\b/i.test(urlStr);
  }
  return false;
}

export interface EvaluatedDecision {
  verdict: StandardVerdict;
  verdictCategory: string; // Authoritative display category
  statusLabel: string;
  badgeColor: 'red' | 'amber' | 'emerald' | 'slate';
  contentSummary: string;
  evidence: string[];
  verifiedClaims: string[];
  unverifiedClaims: string[];
  limitations: string;
  actionRecommended: string;
  fiveQuestions: FiveQuestionsAudit;
  recordAuthenticity: RecordAuthenticityAudit;
  auditReport: StructuredAuditReport;
  emergencyHelplineNeeded: boolean;
  decisionPath?: DecisionPathLog;
}

function buildDecisionPath(params: {
  evaluatedRule: string;
  ruleClause: string;
  ruleRationale: string;
  conditionTruthTable: DecisionPathLog['conditionTruthTable'];
  verdict: StandardVerdict;
  verdictCategory: string;
  badgeColor: 'red' | 'amber' | 'emerald' | 'slate';
  statusLabel: string;
  evidenceItemsCount: number;
}): DecisionPathLog {
  return {
    evaluatedRule: params.evaluatedRule,
    ruleClause: params.ruleClause,
    ruleRationale: params.ruleRationale,
    conditionTruthTable: {
      ...params.conditionTruthTable,
      hasUnexpectedGrantClaim: Boolean(params.conditionTruthTable.hasUnexpectedGrantClaim),
      hasAccountActionViaLink: Boolean(params.conditionTruthTable.hasAccountActionViaLink),
      isShortenedUrl: Boolean(params.conditionTruthTable.isShortenedUrl),
      isUnverifiedShortLink: Boolean(params.conditionTruthTable.isUnverifiedShortLink),
    },
    verdict: params.verdict,
    verdictCategory: params.verdictCategory,
    badgeColor: params.badgeColor,
    statusLabel: params.statusLabel,
    evidenceItemsCount: params.evidenceItemsCount,
  };
}

/**
 * Central Deterministic Classification Policy
 * Evaluates verified facts and outputs a stable, reproducible verdict.
 */
export function evaluateEvidence(input: EvidenceInput): EvaluatedDecision {
  const evidence: string[] = [];
  const verifiedClaims: string[] = [];
  const unverifiedClaims: string[] = [];

  const text = (input.rawText || '').trim();
  const lowerText = text.toLowerCase();
  const sender = (input.sender || '').trim();
  const primaryUrl = (input.urlsExtracted && input.urlsExtracted[0]) || input.qrCodeUrl || '';

  // Extract reference numbers, vehicle registration, and amounts
  const extractedReferenceNumbers: string[] = [...(input.extractedReferenceNumbers || [])];
  const refMatches = text.match(/\b(?:psid|challan\s*(?:no|#)?|ticket\s*(?:no|#)?|trx\s*id|tid|case\s*no|ref\s*no|reference\s*no)[\s.:#-]*([a-zA-Z0-9-]{6,20})/gi);
  if (refMatches) {
    for (const m of refMatches) {
      if (!extractedReferenceNumbers.includes(m)) extractedReferenceNumbers.push(m);
    }
  }

  const extractedAmounts: string[] = [...(input.extractedAmounts || [])];
  const amountMatches = text.match(/\b(?:rs\.?|pkr|php|p|₱)\s*([0-9,]+(?:\.[0-9]{2})?)/gi);
  if (amountMatches) {
    for (const a of amountMatches) {
      if (!extractedAmounts.includes(a)) extractedAmounts.push(a);
    }
  }

  let extractedVehicleDetails = input.extractedVehicleDetails;
  if (!extractedVehicleDetails) {
    const plateMatch = text.match(/\b([A-Z]{2,3}[-\s]?[0-9]{2,4}[-\s]?[0-9]{1,4}|[A-Z]{3}[-\s]?[0-9]{3,4})\b/i);
    if (plateMatch) extractedVehicleDetails = plateMatch[0].toUpperCase();
  }

  // Document category detection
  const isChallanOrFine =
    Boolean(input.isChallanOrFine) ||
    /\b(?:e-challan|echallan|traffic\s+challan|challan\s+no|psid|traffic\s+violation|psca|punjab\s+safe\s+cities|safe\s+city\s+authority|fine\s+amount|speed\s+limit\s+violation|signal\s+violation|traffic\s+warden|mtmis|token\s+tax)\b/i.test(
      lowerText
    );

  const isBankOrTransferReceipt =
    Boolean(input.isBankOrTransferReceipt) ||
    /\b(?:transfer\s+successful|transaction\s+successful|funds\s+transferred|payment\s+successful|receipt|trx\s+id|tid:|sent\s+rs\.?|interbank\s+transfer)\b/i.test(
      lowerText
    );

  // -------------------------------------------------------------
  // Question A: Message Content & Claims
  // -------------------------------------------------------------
  const questionA: QuestionResult = {
    answered: true,
    summary: text
      ? `Text decoded: "${text.length > 120 ? text.slice(0, 117) + '...' : text}"`
      : 'No legible text content found in capture.',
    details: text || 'Image was empty or unreadable.',
  };

  // -------------------------------------------------------------
  // Question B: Suspicious Instructions, Demands & Threats
  // -------------------------------------------------------------
  const detectedScamSignals: string[] = [...(input.scamSignals || [])];

  // Specific scam signature checks
  const isNegatedOtp =
    /(?:never|do\s+not|don't|not\s+to|strictly\s+prohibited|kisi\s+ko\s+na|mat\s+batao|na\s+bhejein)\s+[^.!?\n]*?\b(?:share|send|tell|enter|provide|disclose|give|submit|forward)/i.test(
      lowerText
    );
  const demandsOtp =
    !isNegatedOtp &&
    (/(?:share|send|tell|enter|provide|disclose|give|submit|forward|input|verify|bhejo|dein)\b[^.!?\n]*?\b(?:otp|mpin|pin\s+code|password|passcode|secret\s+code|6-digit\s+code|4-digit\s+code|pin\b)/i.test(
      lowerText
    ) ||
      /(?:otp|mpin|pin\s+code|password)\b[^.!?\n]*?\b(?:send|submit|forward|bhejo|dein|verify)/i.test(
        lowerText
      ) ||
      /otp\s+(?:send|submit|forward)|mpin|pin\s+code/i.test(lowerText));
  if (demandsOtp && !input.isProtectiveAdvisory) {
    detectedScamSignals.push('Demands One-Time Password (OTP) or mobile wallet PIN.');
  }

  const isWarningAboutLottery =
    /(?:beware|caution|warning|alert|fraudulent|fake|never|do\s+not)\s+[^.!?\n]*?\b(?:prize|lottery|inaam|cash\s+grant|wazeefa)/i.test(
      lowerText
    );
  const demandsAdvanceFeeOrLottery =
    !isWarningAboutLottery &&
    /(won|inaam|wazeefa|cash\s+grant|25,000|25000|50,000|lottery|prize)\b/i.test(lowerText) &&
    /(claim|call|wasool|transfer\s+fee|processing\s+fee)/i.test(lowerText);
  if (demandsAdvanceFeeOrLottery && !input.isProtectiveAdvisory) {
    detectedScamSignals.push('Unsolicited advance-fee lottery / cash prize inducement.');
  }

  // Contextual Signal 1: Unexpected government cash assistance or social grant claims
  const hasUnexpectedGrantClaim =
    Boolean(input.hasUnexpectedGrantClaim) ||
    ((/(?:dswd|ayuda|sap\b|social\s+amelioration|cash\s*assistance|emergency\s+subsidy|bisp|ehsaas|wazeefa|relief\s+fund|unsolicited\s+grant|unsolicited\s+subsidy)/i.test(lowerText) ||
      /\b(?:p\s*4700|p4700|rs\.?\s*\d+|php\s*\d+)\b/i.test(lowerText)) &&
      /(?:you\s+received|received|approved|awarded|claim|gratis|ayuda)/i.test(lowerText) &&
      /(?:dswd|ayuda|sap|bisp|ehsaas|grant|subsidy|cash)/i.test(lowerText));
  if (hasUnexpectedGrantClaim && !input.isProtectiveAdvisory) {
    detectedScamSignals.push('Unexpected government cash assistance or social grant claim (DSWD Ayuda / subsidy inducement).');
  }

  // Contextual Signal 2: Request to check, update, unlock or verify account through an external link
  const hasAccountActionViaLink =
    Boolean(input.hasAccountActionViaLink) ||
    (/(?:check(?:\s+your)?\s+balance|update\s+(?:via|your\s+account|info|profile)|verify\s+(?:your\s+account|identity|details)|unlock\s+account|claim\s+via|reactivate)\b[^.!?\n]*?(?:via|at|link|https?:\/\/)/i.test(
      lowerText
    ) ||
      (/(?:balance|update|verify|unlock|claim)\b/i.test(lowerText) &&
        /(?:via|at|click)\s+https?:\/\//i.test(lowerText)));
  if (hasAccountActionViaLink && !input.isProtectiveAdvisory) {
    detectedScamSignals.push('Instructs user to check balance, verify, or update account details via an external web link.');
  }

  // Contextual Signal 3: Shortened URLs hiding the destination
  const isShortenedUrlCandidate =
    Boolean(input.isShortenedUrl) ||
    isShortenedUrl(primaryUrl);
  if (isShortenedUrlCandidate) {
    detectedScamSignals.push('Shortened URL hiding destination address (temporary link shortener service).');
  }

  // Contextual Signal 4: Unverified short link
  const isUnverifiedShortLink = Boolean(input.isUnverifiedShortLink);
  if (isUnverifiedShortLink) {
    detectedScamSignals.push(
      input.unverifiedShortLinkReason ||
        'Destination not verified: Short-link redirect could not be safely resolved to an authenticated domain.'
    );
  }

  // Contextual Signal 5: GCash policy violation (clickable SMS links banned by NTC / GCash security)
  const mentionsGcash = /\b(?:gcash|g-cash)\b/i.test(lowerText);
  if (mentionsGcash && primaryUrl && !input.isProtectiveAdvisory) {
    detectedScamSignals.push(
      'GCash policy violation: Official GCash security policy and telecom regulations strictly ban clickable links in SMS messages.'
    );
  }

  const extortionThreat =
    /(send\s+ransom|private\s+video|private\s+recording|broadcast|blackmail|rupay\s+bhejo\s+warna|avoid\s+arrest|penalty\s+fee|pay\s+penalty|fine\s+immediately|arrest\s+warrant|within\s+2\s+hours|vehicle\s+impound|impound\s+vehicle)/i.test(
      lowerText
    );
  if (extortionThreat) {
    detectedScamSignals.push('Coercive extortion, arrest threat, or penalty fee demand identified.');
  }

  // Private 11-digit mobile SIM impersonation
  const isPrivateSimSender = /^(03\d{2}|(\+92\s?3\d{2}))\s?\d{7}$/.test(sender.replace(/[\s-]/g, ''));
  if (isPrivateSimSender && (demandsOtp || demandsAdvanceFeeOrLottery || input.brandImpersonation?.impersonating)) {
    detectedScamSignals.push(
      `Official claims sent from an unverified private 11-digit mobile SIM (${sender}) rather than an authenticated shortcode.`
    );
  }

  // Traffic Challan specific fraud signals
  const demandsPrivateChallanPayment =
    isChallanOrFine &&
    (/(?:jazzcash|easypaisa|sadapay|upaisa|transfer\s+to\s+03|send\s+to\s+03|call\s+03|account\s+03\d{2})/i.test(
      lowerText
    ) ||
      (isPrivateSimSender && /(?:pay|send|transfer|wasool)/i.test(lowerText)));
  if (demandsPrivateChallanPayment) {
    detectedScamSignals.push(
      'Traffic challan instructs payment to a private mobile number or personal mobile wallet. Official traffic fines are paid strictly via 1Link 1Bill PSID through banks and ATMs.'
    );
  }

  // Deceptive URL Lures & High-Risk TLD Signals
  const linkLures: string[] = [];
  let linkHasHighRiskTld = false;

  const candidateUrls = [...(input.urlsExtracted || [])];
  if (primaryUrl && !candidateUrls.includes(primaryUrl)) {
    candidateUrls.push(primaryUrl);
  }

  for (const u of candidateUrls) {
    let isGovDomain = false;
    try {
      const parsedHost = new URL(u.startsWith('http') ? u : `https://${u}`).hostname.toLowerCase();
      if (
        parsedHost.endsWith('.gov.pk') ||
        parsedHost.endsWith('.gos.pk') ||
        parsedHost.endsWith('.gov.ph') ||
        parsedHost === 'bisp.gov.pk'
      ) {
        isGovDomain = true;
      }
    } catch {}

    if (!isGovDomain && !input.isOfficialGov && !input.isAuthoritativeEntity) {
      const lures = detectScamUrlLures(u);
      for (const l of lures) {
        if (!linkLures.includes(l)) linkLures.push(l);
      }
      if (hasHighRiskTld(u)) {
        linkHasHighRiskTld = true;
      }
    }
  }

  if (linkLures.length > 0 && !input.isProtectiveAdvisory) {
    for (const lure of linkLures) {
      if (!detectedScamSignals.includes(lure)) {
        detectedScamSignals.push(lure);
      }
    }
  }

  if (linkHasHighRiskTld && !input.isProtectiveAdvisory && !input.isOfficialGov) {
    const tldSignal = 'High-risk top-level domain frequently associated with temporary scam landing pages and redirects.';
    if (!detectedScamSignals.includes(tldSignal)) {
      detectedScamSignals.push(tldSignal);
    }
  }

  const questionB: QuestionResult = {
    answered: true,
    summary:
      detectedScamSignals.length > 0
        ? `Suspicious signals detected (${detectedScamSignals.length}): ${detectedScamSignals.join('; ')}`
        : 'No payment demands, credential solicitation, or coercive threats identified.',
    findings:
      detectedScamSignals.length > 0
        ? detectedScamSignals.join('. ')
        : 'Message does not contain coercive threats, OTP requests, or advance fee demands.',
  };

  // -------------------------------------------------------------
  // Question C: Destination URL & Hostname Analysis
  // -------------------------------------------------------------
  let urlFindings = 'No external web address or QR code link identified.';
  let isDeceptiveSub = false;
  let isHomoglyph = false;

  if (primaryUrl) {
    urlFindings = `Analyzed destination URL: ${primaryUrl}.`;
    if (
      primaryUrl.includes('.gov.pk.') ||
      primaryUrl.includes('.gop.pk.') ||
      primaryUrl.includes('.gos.pk.')
    ) {
      isDeceptiveSub = true;
      urlFindings += ' Deceptive Subdomain Attack: Official government domain structure is prepended as a subdomain to an attacker-controlled root domain.';
    }
    if (primaryUrl.includes('xn--')) {
      isHomoglyph = true;
      urlFindings += ' Homograph / Punycode: Non-ASCII look-alike characters detected.';
    }
    if (linkLures.length > 0) {
      urlFindings += ` Deceptive scam lure patterns identified in link: ${linkLures.join('; ')}.`;
    }
    if (linkHasHighRiskTld) {
      urlFindings += ' High-risk top-level domain frequently associated with throwaway scam infrastructure.';
    }
    if (input.brandImpersonation?.impersonating) {
      urlFindings += ` Brand impersonation detected: ${input.brandImpersonation.reason}`;
    }
    if (input.threatIntelResult?.hasThreatMatch) {
      urlFindings += ` Confirmed threat match in global threat index (${input.threatIntelResult.threatTypes?.join(', ')}).`;
    }
  }

  const questionC: QuestionResult = {
    answered: Boolean(primaryUrl),
    summary: primaryUrl ? `URL: ${primaryUrl}` : 'No URL identified.',
    findings: urlFindings,
  };

  // -------------------------------------------------------------
  // Question D: Official Source Corroboration
  // -------------------------------------------------------------
  let corroborationStatus: 'verified_official' | 'contradicted_impersonation' | 'unverified_private' | 'not_applicable' =
    'not_applicable';
  let corroborationDetails = 'No official government or institutional claim required corroboration.';

  if (input.authoritativeEntityName) {
    if (input.isOfficialGov || input.isAuthoritativeEntity) {
      corroborationStatus = 'verified_official';
      corroborationDetails = `Destination or claim matches authoritative registry: ${input.authoritativeEntityName}.`;
      verifiedClaims.push(`Registered under ${input.authoritativeEntityName}.`);
    } else if (input.brandImpersonation?.impersonating) {
      corroborationStatus = 'contradicted_impersonation';
      corroborationDetails = `Claimed affiliation with ${input.brandImpersonation.claimedOrg} is contradicted: official portal is https://${input.brandImpersonation.officialDomain}.`;
      unverifiedClaims.push(
        `Claim of affiliation with ${input.brandImpersonation.claimedOrg} on unofficial destination.`
      );
    }
  }

  const questionD: QuestionResult = {
    answered: corroborationStatus !== 'not_applicable',
    summary: corroborationDetails,
    findings: corroborationDetails,
  };

  // -------------------------------------------------------------
  // Question E: Sender Authentication (Strict Requirement: SMS is NOT carrier-verified)
  // -------------------------------------------------------------
  let senderAuthStatus = 'Sender not independently verified';
  let senderAuthDetails =
    'SMS sender ID or message header is displayed on client device, but carrier-origin transmission cannot be cryptographically verified from a screenshot or public web query. Sender not independently verified.';

  if (sender) {
    if (sender === '1991' || sender === '8171' || sender === '668' || sender === '310' || sender === '333' || sender === '345') {
      senderAuthStatus = 'Sender not independently verified';
      senderAuthDetails = `Header displays recognized shortcode (${sender}). Public website evidence can corroborate advisory content, but carrier transmission cannot be proven from an image alone. Sender not independently verified.`;
    } else if (isPrivateSimSender) {
      senderAuthStatus = 'Sender not independently verified (Unverified private mobile SIM)';
      senderAuthDetails = `Sent from a private mobile connection (${sender}), not an institutional shortcode. Carrier transmission unverified. Sender not independently verified.`;
    } else {
      senderAuthStatus = 'Sender not independently verified';
      senderAuthDetails = `Header displays sender string "${sender}". Carrier origin cannot be proven from an image alone. Sender not independently verified.`;
    }
  }

  const questionE: QuestionResult = {
    answered: true,
    summary: senderAuthStatus,
    findings: senderAuthDetails,
  };

  const fiveQuestions: FiveQuestionsAudit = {
    questionA_messageContent: questionA,
    questionB_suspiciousInstructions: questionB,
    questionC_destinationUrl: questionC,
    questionD_officialCorroboration: questionD,
    questionE_senderAuthenticated: questionE,
  };

  // -------------------------------------------------------------
  // FINAL CLASSIFICATION DECISION LOGIC (Universal 4 Verdicts)
  // -------------------------------------------------------------

  // 1. UNABLE TO VERIFY: Image unreadable, security block, or required verification offline
  if (input.isUnreadableOrEmpty) {
    const unreadableRecordAuth: RecordAuthenticityAudit = {
      status: 'RECORD_NOT_INDEPENDENTLY_VERIFIED',
      label: 'Image Unreadable — Authenticity Cannot Be Evaluated',
      summary: 'Image resolution is too low, cropped, or blurry to inspect reference numbers or text.',
      limitations: 'Forensic inspection requires a clear, complete, legible screenshot.',
    };

    return {
      verdict: 'UNABLE TO VERIFY',
      verdictCategory: 'UNABLE TO VERIFY',
      statusLabel: 'UNABLE TO VERIFY (UNREADABLE OR EMPTY)',
      badgeColor: 'slate',
      contentSummary: input.unreadableReason || 'Image content is too blurry, cropped, or unreadable to evaluate.',
      evidence: ['Decoded text is empty or resolution is insufficient for forensic character recognition.'],
      verifiedClaims: [],
      unverifiedClaims: ['Entire document content is unverified.'],
      limitations: 'Forensic inspection requires a clear, complete, legible screenshot.',
      actionRecommended: 'Upload a higher-resolution, uncropped screenshot of the complete message or notice.',
      fiveQuestions,
      recordAuthenticity: unreadableRecordAuth,
      auditReport: {
        partA_contentAndClaims: {
          summary: 'Unreadable or empty image submission.',
          documentType: input.documentType || 'Unreadable Image',
          extractedReferenceNumbers: [],
          extractedAmounts: [],
        },
        partB_suspiciousRequests: {
          hasScamSignals: false,
          detectedSignals: [],
          demandsCredentials: false,
          coerciveThreats: false,
          unauthorizedPaymentChannel: false,
          summary: 'Could not extract text to evaluate requests.',
        },
        partC_urlAndDomainRisks: {
          hasUrl: false,
          isDeceptiveSubdomain: false,
          isTyposquat: false,
          isHomograph: false,
          isHttpUnencrypted: false,
          summary: 'No readable URL found.',
        },
        partD_officialCorroboration: {
          corroborationStatus: 'not_applicable',
          summary: 'No readable claim to corroborate.',
        },
        partE_senderAuthenticity: {
          isCarrierVerified: false,
          verdict: 'Sender not independently verified',
          summary: 'No sender header readable.',
        },
        partF_recordAuthenticity: unreadableRecordAuth,
        partG_threatIntelligence: {
          checked: false,
          provider: 'None',
          hasThreatMatch: false,
          threatTypes: [],
          summary: 'Threat lookup not applicable for empty text.',
        },
        partH_evidenceQuality: {
          isReadable: false,
          confidence: 'unreadable',
          notes: 'OCR could not decode character glyphs with sufficient confidence.',
        },
        partI_serviceLimitations: {
          unavailableChecks: ['OCR Character Extraction'],
          limitations: ['Image was blurry, cropped, or devoid of text.'],
        },
        partJ_finalVerdict: {
          verdict: 'UNABLE TO VERIFY',
          verdictCategory: 'UNABLE TO VERIFY',
          statusLabel: 'UNABLE TO VERIFY (UNREADABLE OR EMPTY)',
          badgeColor: 'slate',
          threatAssessmentSummary: 'Unable to evaluate threats due to unreadable image.',
          recordAuthenticitySummary: 'Record authenticity cannot be evaluated.',
          actionRecommended: 'Upload a higher-resolution, uncropped screenshot.',
        },
      },
      emergencyHelplineNeeded: false,
    };
  }

  if (input.securityBlockReason) {
    const blockedRecordAuth: RecordAuthenticityAudit = {
      status: 'RECORD_NOT_INDEPENDENTLY_VERIFIED',
      label: 'Security Block — Private Network Address',
      summary: `Destination address failed safety validation: ${input.securityBlockReason}`,
      limitations: 'Cyber Saathi operates within strict public-web boundaries and does not access private endpoints.',
    };

    return {
      verdict: 'UNABLE TO VERIFY',
      verdictCategory: 'UNABLE TO VERIFY',
      statusLabel: 'UNABLE TO VERIFY (SECURITY RESTRICTED)',
      badgeColor: 'slate',
      contentSummary: `Investigation blocked by security policy: ${input.securityBlockReason}`,
      evidence: [
        `Destination address failed safety validation: ${input.securityBlockReason}`,
        'Access to private IP ranges, loopback endpoints, and internal infrastructure is strictly blocked (SSRF defense).',
      ],
      verifiedClaims: [],
      unverifiedClaims: ['Target endpoint was not contacted.'],
      limitations: 'Cyber Saathi operates within strict public-web boundaries and does not access private endpoints.',
      actionRecommended: 'Verify that the web address is a public internet URL and not an internal network address.',
      fiveQuestions,
      recordAuthenticity: blockedRecordAuth,
      auditReport: {
        partA_contentAndClaims: {
          summary: `URL target blocked: ${primaryUrl}`,
          documentType: 'Web Address / Network Target',
          extractedReferenceNumbers: [],
          extractedAmounts: [],
        },
        partB_suspiciousRequests: {
          hasScamSignals: false,
          detectedSignals: [],
          demandsCredentials: false,
          coerciveThreats: false,
          unauthorizedPaymentChannel: false,
          summary: 'Security policy blocked endpoint connection.',
        },
        partC_urlAndDomainRisks: {
          hasUrl: true,
          primaryUrl,
          isDeceptiveSubdomain: false,
          isTyposquat: false,
          isHomograph: false,
          isHttpUnencrypted: false,
          summary: `Security block: ${input.securityBlockReason}`,
        },
        partD_officialCorroboration: {
          corroborationStatus: 'not_applicable',
          summary: 'Private IP target cannot be corroborated against civic registry.',
        },
        partE_senderAuthenticity: {
          isCarrierVerified: false,
          verdict: 'Sender not independently verified',
          summary: 'Not applicable to direct network target.',
        },
        partF_recordAuthenticity: blockedRecordAuth,
        partG_threatIntelligence: {
          checked: false,
          provider: 'Local SSRF Gateway',
          hasThreatMatch: false,
          threatTypes: [],
          summary: 'Target resolved to private or reserved IP space.',
        },
        partH_evidenceQuality: {
          isReadable: true,
          confidence: 'high',
          notes: 'URL parsed and matched against RFC 1918 / loopback ranges.',
        },
        partI_serviceLimitations: {
          unavailableChecks: ['Remote Webpage Inspection'],
          limitations: ['Internal and private addresses are blocked by SSRF firewall.'],
        },
        partJ_finalVerdict: {
          verdict: 'UNABLE TO VERIFY',
          verdictCategory: 'UNABLE TO VERIFY',
          statusLabel: 'UNABLE TO VERIFY (SECURITY RESTRICTED)',
          badgeColor: 'slate',
          threatAssessmentSummary: 'Target endpoint was blocked by security policy.',
          recordAuthenticitySummary: 'Private network address cannot be corroborated.',
          actionRecommended: 'Verify that the web address is a public internet URL.',
        },
      },
      emergencyHelplineNeeded: false,
    };
  }

  // 2. CONFIRMED THREAT: Definite threat intel match or demonstrable active fraud
  const hasConfirmedThreatIntel = Boolean(input.threatIntelResult?.hasThreatMatch);
  const hasBrandImpersonation = Boolean(input.brandImpersonation?.impersonating);
  const isDirectDeceptiveDomain =
    hasBrandImpersonation &&
    !isShortenedUrlCandidate &&
    !isShortenedUrl(primaryUrl);

  const hasActiveFraudSignals =
    demandsOtp ||
    extortionThreat ||
    demandsPrivateChallanPayment ||
    isDeceptiveSub ||
    isHomoglyph ||
    isDirectDeceptiveDomain ||
    (linkLures.length > 0 && linkHasHighRiskTld) ||
    (linkLures.length > 0 && (isShortenedUrlCandidate || isShortenedUrl(primaryUrl))) ||
    (demandsAdvanceFeeOrLottery && isPrivateSimSender) ||
    Boolean(input.destinationPageInfo?.hasLoginForm) ||
    (isDirectDeceptiveDomain && (demandsOtp || demandsAdvanceFeeOrLottery || primaryUrl || isChallanOrFine));

  if (hasConfirmedThreatIntel || hasActiveFraudSignals || (isDirectDeceptiveDomain && primaryUrl)) {
    if (hasConfirmedThreatIntel) {
      evidence.push(
        `Direct threat match in global threat intelligence database: ${input.threatIntelResult?.threatTypes?.join(', ')}.`
      );
      verifiedClaims.push('Threat match confirmed by global threat-intelligence registry.');
    }
    if (hasBrandImpersonation) {
      evidence.push(
        input.brandImpersonation?.reason ||
          `Domain mimics ${input.brandImpersonation?.claimedOrg} on an unofficial host.`
      );
      verifiedClaims.push(
        `Authentic portal for ${input.brandImpersonation?.claimedOrg} is strictly https://${input.brandImpersonation?.officialDomain}`
      );
      unverifiedClaims.push(
        `Submitted link has no verifiable connection to ${input.brandImpersonation?.claimedOrg}.`
      );
    }
    for (const sig of detectedScamSignals) {
      if (!evidence.includes(sig)) evidence.push(sig);
    }

    const threatRecordAuth: RecordAuthenticityAudit = {
      status: 'CONTRADICTED_BY_OFFICIAL_RECORD',
      label: 'Fraudulent Claim — Contradicted by Official Civic Rules',
      summary: isChallanOrFine
        ? 'Official traffic challans in Pakistan are paid strictly via 1Link 1Bill PSID through banks and ATMs. Demanding direct payment to a private mobile number or unverified website is fraudulent.'
        : 'Claim contradicts official institutional payment rails and verified communication policies.',
      officialVerificationUrl: input.brandImpersonation?.officialDomain
        ? `https://${input.brandImpersonation.officialDomain}`
        : 'https://complaint.nccia.gov.pk',
      limitations: 'Tangible fraudulent markers identified in message context or destination URL.',
    };

    return {
      verdict: 'CONFIRMED THREAT',
      verdictCategory: 'CONFIRMED THREAT',
      statusLabel: hasConfirmedThreatIntel
        ? 'CONFIRMED THREAT (GLOBAL BLOCKLIST)'
        : isChallanOrFine
        ? 'CONFIRMED THREAT (FRAUDULENT CHALLAN & EXTORTION)'
        : 'CONFIRMED THREAT (DECEPTIVE FRAUD ATTEMPT)',
      badgeColor: 'red',
      contentSummary: hasConfirmedThreatIntel
        ? `This destination is a confirmed active security threat (${input.threatIntelResult?.threatTypes?.join(', ')}).`
        : isChallanOrFine
        ? 'Fraudulent traffic challan detected: demands payment to an unverified private mobile account or unofficial link.'
        : `Strong evidence of fraud: Unsolicited credential demands, extortion threats, or brand impersonation detected.`,
      evidence,
      verifiedClaims,
      unverifiedClaims,
      limitations: 'Investigation established tangible threat indicators. Never disclose credentials or send funds.',
      actionRecommended: isChallanOrFine
        ? 'Do NOT transfer funds to this private number. Check your vehicle challan status directly on the official Punjab e-Challan portal (https://echallan.psca.gop.pk) or Sindh Police portal.'
        : 'Do NOT click the link, do NOT disclose OTPs or passwords, and block the sender immediately. If you lost funds, call FIA/NCCIA Helpline 1991.',
      fiveQuestions,
      recordAuthenticity: threatRecordAuth,
      auditReport: {
        partA_contentAndClaims: {
          summary: text ? text.slice(0, 150) : 'Capture decoded.',
          documentType: input.documentType || (isChallanOrFine ? 'Traffic E-Challan / Fine Notice' : 'Digital Screenshot'),
          extractedReferenceNumbers,
          extractedVehicleDetails,
          extractedAmounts,
          claimedIssuingAuthority: input.brandImpersonation?.claimedOrg || input.apparentOrg,
        },
        partB_suspiciousRequests: {
          hasScamSignals: true,
          detectedSignals: detectedScamSignals,
          demandsCredentials: Boolean(demandsOtp),
          coerciveThreats: Boolean(extortionThreat),
          unauthorizedPaymentChannel: Boolean(demandsPrivateChallanPayment || (demandsAdvanceFeeOrLottery && isPrivateSimSender)),
          summary: detectedScamSignals.join('; '),
        },
        partC_urlAndDomainRisks: {
          hasUrl: Boolean(primaryUrl),
          primaryUrl,
          domain: input.brandImpersonation?.officialDomain,
          isDeceptiveSubdomain: isDeceptiveSub,
          isTyposquat: Boolean(hasBrandImpersonation),
          isHomograph: isHomoglyph,
          isHttpUnencrypted: Boolean(primaryUrl && primaryUrl.startsWith('http://')),
          summary: urlFindings,
        },
        partD_officialCorroboration: {
          claimedEntity: input.brandImpersonation?.claimedOrg,
          officialPortal: input.brandImpersonation?.officialDomain,
          corroborationStatus: 'contradicted_impersonation',
          summary: `Deceptive destination contradicts official portal https://${input.brandImpersonation?.officialDomain || 'gov.pk'}.`,
        },
        partE_senderAuthenticity: {
          senderString: sender,
          isCarrierVerified: false,
          verdict: 'Sender not independently verified',
          summary: senderAuthDetails,
        },
        partF_recordAuthenticity: threatRecordAuth,
        partG_threatIntelligence: {
          checked: Boolean(input.threatIntelResult?.checked),
          provider: 'Google Safe Browsing & Heuristic Engine',
          hasThreatMatch: hasConfirmedThreatIntel,
          threatTypes: input.threatIntelResult?.threatTypes || [],
          summary: hasConfirmedThreatIntel
            ? `Threat match confirmed: ${input.threatIntelResult?.threatTypes?.join(', ')}`
            : 'Threat intelligence lookup completed; classification established by verified fraud signals.',
        },
        partH_evidenceQuality: {
          isReadable: true,
          confidence: 'high',
          notes: 'High confidence character decoding and pattern matching.',
        },
        partI_serviceLimitations: {
          unavailableChecks: [],
          limitations: ['Classification determined by positive forensic markers.'],
        },
        partJ_finalVerdict: {
          verdict: 'CONFIRMED THREAT',
          verdictCategory: 'CONFIRMED THREAT',
          statusLabel: 'CONFIRMED THREAT (DECEPTIVE FRAUD ATTEMPT)',
          badgeColor: 'red',
          threatAssessmentSummary: 'Tangible fraudulent markers established.',
          recordAuthenticitySummary: 'Contradicted by verified official policies.',
          actionRecommended: 'Do NOT disclose credentials or send funds.',
        },
      },
      emergencyHelplineNeeded: Boolean(demandsOtp || extortionThreat || (demandsAdvanceFeeOrLottery && isPrivateSimSender)),
    };
  }

  // 3. SUSPICIOUS: Meaningful warning signs present, but insufficient evidence of active malice
  const isSuspiciousUrl = Boolean(
    primaryUrl &&
    (linkHasHighRiskTld ||
      linkLures.length > 0 ||
      primaryUrl.includes('.xyz') ||
      primaryUrl.includes('.top') ||
      primaryUrl.includes('.click') ||
      primaryUrl.includes('.buzz') ||
      (primaryUrl.startsWith('http://') && !input.isOfficialGov))
  );

  const hasUnverifiedLinkInPrivateSms = isPrivateSimSender && primaryUrl && !input.isOfficialGov;
  const hasSuspiciousSignals =
    detectedScamSignals.length > 0 ||
    isSuspiciousUrl ||
    hasUnverifiedLinkInPrivateSms ||
    isShortenedUrlCandidate ||
    isUnverifiedShortLink ||
    hasUnexpectedGrantClaim ||
    hasAccountActionViaLink ||
    hasBrandImpersonation;

  if (hasSuspiciousSignals) {
    if (primaryUrl.startsWith('http://') && !input.isOfficialGov && !evidence.some((e) => e.includes('Unencrypted HTTP'))) {
      evidence.push('Unencrypted HTTP protocol on an external web address.');
    }
    if (linkHasHighRiskTld && !evidence.some((e) => e.includes('High-risk top-level domain'))) {
      evidence.push('High-risk top-level domain frequently associated with temporary scam landing pages and redirects.');
    }
    if (linkLures.length > 0) {
      for (const lure of linkLures) {
        if (!evidence.includes(lure)) evidence.push(lure);
      }
    }
    if (hasUnverifiedLinkInPrivateSms && !evidence.some((e) => e.includes('private 11-digit mobile SIM'))) {
      evidence.push(`Unsolicited link sent from a private 11-digit mobile SIM (${sender}).`);
    }
    if (isShortenedUrlCandidate && !evidence.some((e) => e.includes('Shortened URL masks'))) {
      evidence.push('Shortened URL masks the true destination address. Shorteners are frequently used to hide deceptive landing pages.');
    }
    if (isUnverifiedShortLink && !evidence.some((e) => e.includes('Destination not verified'))) {
      evidence.push('Destination not verified: The actual target website has not been independently established through safe server expansion.');
    }
    if (hasUnexpectedGrantClaim && !evidence.some((e) => e.includes('Unexpected government cash assistance'))) {
      evidence.push('Unexpected government cash assistance / Ayuda claim: Official aid is distributed through designated local government channels, not unsolicited SMS links.');
    }
    if (hasAccountActionViaLink && !evidence.some((e) => e.includes('Demands account balance check'))) {
      evidence.push('Demands account balance check or update via external link: Legitimate financial and government entities do not direct users to verify accounts through external SMS links.');
    }
    if (mentionsGcash && primaryUrl && !evidence.some((e) => e.includes('GCash security policy'))) {
      evidence.push('GCash security policy: NTC regulations and GCash strictly prohibit clickable links in SMS messages.');
    }
    for (const sig of detectedScamSignals) {
      if (!evidence.includes(sig)) evidence.push(sig);
    }

    unverifiedClaims.push(
      'CRITICAL: An empty threat intelligence response is NEVER proof that an unfamiliar website or short link is genuine or safe.'
    );
    unverifiedClaims.push('Sender identity cannot be authenticated from screenshot or message header.');
    if (isShortenedUrlCandidate) {
      unverifiedClaims.push('Exact destination address and transaction authenticity have not been independently established.');
    }

    const suspiciousRecordAuth: RecordAuthenticityAudit = {
      status: 'RECORD_NOT_INDEPENDENTLY_VERIFIED',
      label: 'Record Not Independently Verified',
      summary: hasUnexpectedGrantClaim
        ? 'Unexpected social assistance or financial claim. Transaction authenticity and destination link are unverified.'
        : 'Communication exhibits anomalous warning signs. Authenticity cannot be established.',
      officialVerificationUrl: hasUnexpectedGrantClaim
        ? 'https://www.dswd.gov.ph'
        : mentionsGcash
        ? 'https://www.gcash.com'
        : undefined,
      limitations: 'Warning signs detected, but insufficient evidence to conclusively prove fraud. Treat with high skepticism.',
    };

    const decisionPath = buildDecisionPath({
      evaluatedRule: 'POLICY_RULE_3_SUSPICIOUS',
      ruleClause: '3.1_ANOMALOUS_WARNING_SIGNS',
      ruleRationale:
        'Contextual scam signals, shortened unverified link, or unexpected grant claims detected without conclusive active threat match.',
      conditionTruthTable: {
        hasConfirmedThreatIntel,
        hasBrandImpersonation,
        hasActiveFraudSignals,
        demandsOtp: Boolean(demandsOtp),
        isNegatedOtp: Boolean(isNegatedOtp),
        demandsAdvanceFeeOrLottery: Boolean(demandsAdvanceFeeOrLottery),
        extortionThreat: Boolean(extortionThreat),
        demandsPrivateChallanPayment: Boolean(demandsPrivateChallanPayment),
        isPrivateSimSender: Boolean(isPrivateSimSender),
        isDeceptiveSubdomain: Boolean(isDeceptiveSub),
        isHomoglyph: Boolean(isHomoglyph),
        isSuspiciousUrl: Boolean(isSuspiciousUrl),
        hasUnverifiedLinkInPrivateSms: Boolean(hasUnverifiedLinkInPrivateSms),
        hasSecurityBlock: false,
        isUnreadableOrEmpty: false,
        hasUnexpectedGrantClaim: Boolean(hasUnexpectedGrantClaim),
        hasAccountActionViaLink: Boolean(hasAccountActionViaLink),
        isShortenedUrl: Boolean(isShortenedUrlCandidate),
        isUnverifiedShortLink: Boolean(isUnverifiedShortLink),
      },
      verdict: 'SUSPICIOUS',
      verdictCategory: 'SUSPICIOUS',
      badgeColor: 'amber',
      statusLabel: 'SUSPICIOUS — INVESTIGATION NEEDED',
      evidenceItemsCount: evidence.length,
    });

    return {
      verdict: 'SUSPICIOUS',
      verdictCategory: 'SUSPICIOUS',
      statusLabel: 'SUSPICIOUS — INVESTIGATION NEEDED',
      badgeColor: 'amber',
      contentSummary: hasUnexpectedGrantClaim && mentionsGcash
        ? 'Suspicious cash assistance alert claiming DSWD Ayuda via GCash with an external shortened link. GCash strictly prohibits clickable SMS links, and the short-link destination has not been verified.'
        : 'Warning signs identified. The communication or web link exhibits anomalous characteristics and should be handled with extreme caution.',
      evidence,
      verifiedClaims,
      unverifiedClaims,
      limitations: 'Warning signs detected, but insufficient evidence to conclusively prove fraud. Treat with high skepticism.',
      actionRecommended: (hasUnexpectedGrantClaim || mentionsGcash)
        ? 'Do NOT click the external link. Do NOT enter MPIN, passwords, or personal details. Verify cash aid directly with official DSWD channels (https://www.dswd.gov.ph) and check your balance only within the official GCash mobile app.'
        : 'Do NOT enter passwords, banking PINs, or personal CNIC details. Verify the message via official organizational channels.',
      fiveQuestions,
      recordAuthenticity: suspiciousRecordAuth,
      decisionPath,
      auditReport: {
        partA_contentAndClaims: {
          summary: text ? text.slice(0, 150) : 'Suspicious capture.',
          documentType: input.documentType || 'Digital Screenshot',
          extractedReferenceNumbers,
          extractedVehicleDetails,
          extractedAmounts,
        },
        partB_suspiciousRequests: {
          hasScamSignals: true,
          detectedSignals: detectedScamSignals,
          demandsCredentials: false,
          coerciveThreats: false,
          unauthorizedPaymentChannel: false,
          summary: 'Inconclusive warning signs present.',
        },
        partC_urlAndDomainRisks: {
          hasUrl: Boolean(primaryUrl),
          primaryUrl,
          isDeceptiveSubdomain: isDeceptiveSub,
          isTyposquat: false,
          isHomograph: isHomoglyph,
          isHttpUnencrypted: Boolean(primaryUrl && primaryUrl.startsWith('http://')),
          summary: urlFindings,
        },
        partD_officialCorroboration: {
          corroborationStatus: 'unverified_private',
          summary: 'Domain or message lacks institutional corroboration.',
        },
        partE_senderAuthenticity: {
          senderString: sender,
          isCarrierVerified: false,
          verdict: 'Sender not independently verified',
          summary: senderAuthDetails,
        },
        partF_recordAuthenticity: suspiciousRecordAuth,
        partG_threatIntelligence: {
          checked: Boolean(input.threatIntelResult?.checked),
          provider: 'Google Safe Browsing',
          hasThreatMatch: false,
          threatTypes: [],
          summary: 'No threat intelligence blocklist match found, but warning signs remain.',
        },
        partH_evidenceQuality: {
          isReadable: true,
          confidence: 'medium',
          notes: 'Evidence exhibits ambiguous or unverified signals.',
        },
        partI_serviceLimitations: {
          unavailableChecks: ['Private Subscriber Identity Verification'],
          limitations: ['Cannot confirm carrier-level sender origin.'],
        },
        partJ_finalVerdict: {
          verdict: 'SUSPICIOUS',
          verdictCategory: 'SUSPICIOUS',
          statusLabel: 'SUSPICIOUS — INVESTIGATION NEEDED',
          badgeColor: 'amber',
          threatAssessmentSummary: 'Warning signs identified without conclusive malicious proof.',
          recordAuthenticitySummary: 'Record not verified.',
          actionRecommended: 'Do NOT disclose sensitive information.',
        },
      },
      emergencyHelplineNeeded: false,
    };
  }

  // 4. NO KNOWN THREAT FOUND: Clean civic notice, genuine public advisory, routine telco notification, or unverified challan
  if (isChallanOrFine) {
    // Challan without malicious links or extortion
    evidence.push('Challan / traffic violation format recognized with reference numbers and vehicle details.');
    evidence.push('Contains no direct private mobile wallet payment demands or malicious links.');
    unverifiedClaims.push(
      'CRITICAL: A realistic challan layout is NEVER proof of authenticity. Cyber Saathi does NOT access private police enforcement or provincial tax databases.'
    );
    unverifiedClaims.push(
      'Challan violation validity must be independently confirmed on the official provincial portal.'
    );

    const challanRecordAuth: RecordAuthenticityAudit = {
      status: 'RECORD_NOT_INDEPENDENTLY_VERIFIED',
      label: 'Challan authenticity not independently verified',
      summary:
        'Public automated record verification without citizen credentials or CAPTCHA is not exposed by the official portal. Cyber Saathi does not access private police enforcement or provincial tax databases.',
      officialVerificationUrl: 'https://echallan.psca.gop.pk',
      limitations:
        'Challan details parsed, but validity of this violation record cannot be confirmed from an image alone. Check directly on the official portal.',
    };

    return {
      verdict: 'NO KNOWN THREAT FOUND',
      verdictCategory: 'NO KNOWN THREAT FOUND',
      statusLabel: 'NO KNOWN THREAT FOUND — CHALLAN RECORD UNVERIFIED',
      badgeColor: 'slate', // Neutral slate, NOT emerald, to avoid misleading users into thinking the challan is verified genuine!
      contentSummary:
        'Challan details parsed. No malicious links, private wallet payment demands, or extortion threats detected. However, this specific violation record has NOT been verified against the police database.',
      evidence,
      verifiedClaims: ['No active scam signatures, private mobile numbers, or malicious URLs detected in scan.'],
      unverifiedClaims,
      limitations:
        'Cyber Saathi evaluates observable digital indicators. It does not access private police enforcement databases or provincial tax records.',
      actionRecommended:
        'To verify and pay this challan, visit the official Punjab e-Challan portal at https://echallan.psca.gop.pk or Sindh Traffic Police portal directly using your vehicle registration and CNIC.',
      fiveQuestions,
      recordAuthenticity: challanRecordAuth,
      auditReport: {
        partA_contentAndClaims: {
          summary: text.slice(0, 150),
          documentType: 'Traffic E-Challan / Violation Notice',
          extractedReferenceNumbers,
          extractedVehicleDetails,
          extractedAmounts,
          claimedIssuingAuthority: input.authoritativeEntityName || 'Punjab Safe Cities Authority (PSCA) / Traffic Police',
        },
        partB_suspiciousRequests: {
          hasScamSignals: false,
          detectedSignals: [],
          demandsCredentials: false,
          coerciveThreats: false,
          unauthorizedPaymentChannel: false,
          summary: 'No fraudulent payment demands or extortion threats found.',
        },
        partC_urlAndDomainRisks: {
          hasUrl: Boolean(primaryUrl),
          primaryUrl,
          isDeceptiveSubdomain: false,
          isTyposquat: false,
          isHomograph: false,
          isHttpUnencrypted: false,
          summary: primaryUrl ? `URL: ${primaryUrl}` : 'No external URL in challan.',
        },
        partD_officialCorroboration: {
          claimedEntity: 'Traffic Police / PSCA',
          officialPortal: 'https://echallan.psca.gop.pk',
          corroborationStatus: 'unverified_private',
          summary: 'Claimed issuing authority recognized; individual violation ticket not verified.',
        },
        partE_senderAuthenticity: {
          senderString: sender,
          isCarrierVerified: false,
          verdict: 'Sender not independently verified',
          summary: senderAuthDetails,
        },
        partF_recordAuthenticity: challanRecordAuth,
        partG_threatIntelligence: {
          checked: Boolean(input.threatIntelResult?.checked),
          provider: 'Google Safe Browsing',
          hasThreatMatch: false,
          threatTypes: [],
          summary: 'No threat intelligence blocklist matches found.',
        },
        partH_evidenceQuality: {
          isReadable: true,
          confidence: 'high',
          notes: 'Vehicle registration and reference numbers extracted successfully.',
        },
        partI_serviceLimitations: {
          unavailableChecks: ['Police Traffic Enforcement Database Lookup'],
          limitations: ['Official enforcement database requires CAPTCHA / citizen login.'],
        },
        partJ_finalVerdict: {
          verdict: 'NO KNOWN THREAT FOUND',
          verdictCategory: 'NO KNOWN THREAT FOUND',
          statusLabel: 'NO KNOWN THREAT FOUND — CHALLAN RECORD UNVERIFIED',
          badgeColor: 'slate',
          threatAssessmentSummary: 'No malicious links or extortion demands detected in capture.',
          recordAuthenticitySummary: 'Challan authenticity not independently verified against police database.',
          actionRecommended: 'Verify on https://echallan.psca.gop.pk before payment.',
        },
      },
      emergencyHelplineNeeded: false,
    };
  }

  if (isBankOrTransferReceipt) {
    evidence.push('Banking or mobile wallet transfer receipt format recognized.');
    evidence.push('Contains no phishing links or unsolicited credential solicitations.');
    unverifiedClaims.push(
      'CRITICAL: A payment confirmation screenshot can be digitally edited. Cyber Saathi does NOT access private banking ledgers or interbank networks.'
    );

    const receiptRecordAuth: RecordAuthenticityAudit = {
      status: 'RECORD_NOT_INDEPENDENTLY_VERIFIED',
      label: 'Transfer confirmation not independently verified',
      summary:
        'Banking transfer receipts can be easily fabricated or digitally edited. Cyber Saathi does not access private banking databases. Verify whether funds have actually arrived by checking your official banking app directly.',
      limitations: 'Image alone cannot verify whether interbank funds were actually settled.',
    };

    return {
      verdict: 'NO KNOWN THREAT FOUND',
      verdictCategory: 'NO KNOWN THREAT FOUND',
      statusLabel: 'NO KNOWN THREAT FOUND — RECEIPT NOT INDEPENDENTLY VERIFIED',
      badgeColor: 'slate',
      contentSummary:
        'Payment confirmation details parsed. No malicious links or phishing forms detected. However, transfer receipt authenticity cannot be independently verified from an image.',
      evidence,
      verifiedClaims: ['No malicious links or phishing signatures detected.'],
      unverifiedClaims,
      limitations: 'Cannot verify interbank transfer completion without banking app ledger access.',
      actionRecommended: 'Check your official banking or wallet app balance directly to confirm funds received.',
      fiveQuestions,
      recordAuthenticity: receiptRecordAuth,
      auditReport: {
        partA_contentAndClaims: {
          summary: text.slice(0, 150),
          documentType: 'Banking / Mobile Wallet Transfer Receipt',
          extractedReferenceNumbers,
          extractedAmounts,
        },
        partB_suspiciousRequests: {
          hasScamSignals: false,
          detectedSignals: [],
          demandsCredentials: false,
          coerciveThreats: false,
          unauthorizedPaymentChannel: false,
          summary: 'No suspicious requests detected.',
        },
        partC_urlAndDomainRisks: {
          hasUrl: Boolean(primaryUrl),
          primaryUrl,
          isDeceptiveSubdomain: false,
          isTyposquat: false,
          isHomograph: false,
          isHttpUnencrypted: false,
          summary: 'No malicious URLs identified.',
        },
        partD_officialCorroboration: {
          corroborationStatus: 'not_applicable',
          summary: 'Private transaction receipt.',
        },
        partE_senderAuthenticity: {
          isCarrierVerified: false,
          verdict: 'Sender not independently verified',
          summary: senderAuthDetails,
        },
        partF_recordAuthenticity: receiptRecordAuth,
        partG_threatIntelligence: {
          checked: false,
          provider: 'None',
          hasThreatMatch: false,
          threatTypes: [],
          summary: 'Threat intel not applicable to private receipt.',
        },
        partH_evidenceQuality: {
          isReadable: true,
          confidence: 'high',
          notes: 'Transaction details decoded.',
        },
        partI_serviceLimitations: {
          unavailableChecks: ['Interbank 1Link Ledger Verification'],
          limitations: ['Private transaction records cannot be queried publicly.'],
        },
        partJ_finalVerdict: {
          verdict: 'NO KNOWN THREAT FOUND',
          verdictCategory: 'NO KNOWN THREAT FOUND',
          statusLabel: 'NO KNOWN THREAT FOUND — RECEIPT NOT INDEPENDENTLY VERIFIED',
          badgeColor: 'slate',
          threatAssessmentSummary: 'No malicious signatures detected in capture.',
          recordAuthenticitySummary: 'Transfer receipt not independently verified.',
          actionRecommended: 'Confirm directly in your banking app.',
        },
      },
      emergencyHelplineNeeded: false,
    };
  }

  if (input.isProtectiveAdvisory) {
    evidence.push('Genuine public safety advisory warning citizens against credential theft and digital fraud.');
    evidence.push('Actively advises citizens NEVER to share OTPs, PINs, or banking passwords.');
    evidence.push('Features authentic official reporting hotlines (FIA 1991 / BISP 8171 / PTA 668).');
    verifiedClaims.push('Advisory content aligns with national cyber safety guidance.');
  } else if (sender === '668' || lowerText.includes('total active sims') || lowerText.includes('cnic.sims.pk')) {
    evidence.push('Format is consistent with standard PTA SIM count disclosure from shortcode 668.');
    evidence.push('Contains no payment demands, OTP solicitations, or coercive lockout threats.');
    verifiedClaims.push('668 is the designated official shortcode for PTA SIM count information in Pakistan.');
    unverifiedClaims.push(
      'Specific subscriber SIM count cannot be independently checked without access to secure telecom databases.'
    );
  } else if (
    sender === '310' ||
    sender === '333' ||
    sender === '345' ||
    sender.toLowerCase() === 'zong' ||
    sender.toLowerCase() === 'ufone' ||
    sender.toLowerCase() === 'telenor'
  ) {
    const carrierBrand =
      sender === '310' || sender.toLowerCase() === 'zong'
        ? 'ZONG (CMPak)'
        : sender === '333' || sender.toLowerCase() === 'ufone'
        ? 'UFONE (PTML)'
        : sender === '345' || sender.toLowerCase() === 'telenor'
        ? 'TELENOR'
        : sender.toUpperCase();
    evidence.push(`Routine telecom notification format consistent with ${carrierBrand}.`);
    evidence.push('No suspicious instructions, prize claims, or payment links identified.');
    unverifiedClaims.push(
      'Carrier-level SMS transmission cannot be verified from a screenshot. However, content contains no malicious signatures.'
    );
  } else if (input.isOfficialGov || input.isAuthoritativeEntity) {
    evidence.push(`Domain is authenticated under verified registry: ${input.authoritativeEntityName || 'Official Gateway'}.`);
    if (input.destinationPageInfo?.retrieved) {
      evidence.push(`Server returned HTTP ${input.destinationPageInfo.httpStatus || 200}. Page was accessible.`);
    }
    verifiedClaims.push(`Domain is authenticated in the official public registry.`);
  } else {
    evidence.push('Scanned against global threat databases and local threat heuristic signatures.');
    evidence.push('No malicious indicators, brand spoofing, or credential harvesting forms detected.');
    unverifiedClaims.push(
      'CRITICAL: The absence of a threat report or clean threat intelligence response is NEVER a guarantee of safety or authenticity. New phishing websites may evade blocklists initially.'
    );
  }

  const defaultRecordAuth: RecordAuthenticityAudit = {
    status: (input.isOfficialGov || input.isProtectiveAdvisory) ? 'OFFICIAL_RECORD_VERIFIED' : 'NOT_APPLICABLE',
    label: (input.isOfficialGov || input.isProtectiveAdvisory)
      ? 'Official Public Source Corroborated'
      : 'General Public Communication',
    summary: (input.isOfficialGov || input.isProtectiveAdvisory)
      ? `Corroborated against official public records of ${input.authoritativeEntityName || 'Government of Pakistan'}.`
      : 'Standard communication evaluated against public threat indicators.',
    officialVerificationUrl: input.authoritativeEntityName ? 'https://pakistan.gov.pk' : undefined,
    limitations: 'Public threat scanning does not access private institutional databases.',
  };

  return {
    verdict: 'NO KNOWN THREAT FOUND',
    verdictCategory: 'NO KNOWN THREAT FOUND',
    statusLabel: input.isProtectiveAdvisory
      ? 'NO KNOWN THREAT FOUND (GENUINE CIVIC ADVISORY)'
      : input.isOfficialGov
      ? 'NO KNOWN THREAT FOUND (OFFICIAL REGISTRY MATCH)'
      : 'NO KNOWN THREAT FOUND',
    badgeColor: 'emerald',
    contentSummary: input.isProtectiveAdvisory
      ? 'Genuine public cyber safety notice. Educates citizens against fraud and does not request sensitive data.'
      : input.isOfficialGov
      ? `Official domain verified for ${input.authoritativeEntityName || 'government department'}. No security threat records found.`
      : 'Scanned against available public threat records. No known threat matches or scam patterns detected.',
    evidence,
    verifiedClaims,
    unverifiedClaims,
    limitations:
      'Evaluated against available public threat records and observable content at scan time. Cyber Saathi does not access private telecom subscriber records or confidential government accounts.',
    actionRecommended:
      'Practice standard cyber hygiene. Never disclose your passwords, PINs, or SMS OTPs to any caller or website.',
    fiveQuestions,
    recordAuthenticity: defaultRecordAuth,
    auditReport: {
      partA_contentAndClaims: {
        summary: text ? text.slice(0, 150) : 'Clean communication capture.',
        documentType: input.documentType || 'Digital Communication',
        extractedReferenceNumbers,
        extractedAmounts,
      },
      partB_suspiciousRequests: {
        hasScamSignals: false,
        detectedSignals: [],
        demandsCredentials: false,
        coerciveThreats: false,
        unauthorizedPaymentChannel: false,
        summary: 'No suspicious instructions or threats detected.',
      },
      partC_urlAndDomainRisks: {
        hasUrl: Boolean(primaryUrl),
        primaryUrl,
        isDeceptiveSubdomain: false,
        isTyposquat: false,
        isHomograph: false,
        isHttpUnencrypted: Boolean(primaryUrl && primaryUrl.startsWith('http://')),
        summary: urlFindings,
      },
      partD_officialCorroboration: {
        claimedEntity: input.authoritativeEntityName,
        corroborationStatus: (input.isOfficialGov || input.isProtectiveAdvisory) ? 'verified_official' : 'not_applicable',
        summary: corroborationDetails,
      },
      partE_senderAuthenticity: {
        senderString: sender,
        isCarrierVerified: false,
        verdict: 'Sender not independently verified',
        summary: senderAuthDetails,
      },
      partF_recordAuthenticity: defaultRecordAuth,
      partG_threatIntelligence: {
        checked: Boolean(input.threatIntelResult?.checked),
        provider: 'Google Safe Browsing & Heuristic Engine',
        hasThreatMatch: false,
        threatTypes: [],
        summary: 'No threat intelligence matches or malware blocklist records found.',
      },
      partH_evidenceQuality: {
        isReadable: true,
        confidence: 'high',
        notes: 'Observable facts evaluated cleanly against official rules.',
      },
      partI_serviceLimitations: {
        unavailableChecks: [],
        limitations: ['Clean scan is never a guarantee of authenticity for private records.'],
      },
      partJ_finalVerdict: {
        verdict: 'NO KNOWN THREAT FOUND',
        verdictCategory: 'NO KNOWN THREAT FOUND',
        statusLabel: 'NO KNOWN THREAT FOUND',
        badgeColor: 'emerald',
        threatAssessmentSummary: 'No known security threat records or fraud signatures found.',
        recordAuthenticitySummary: defaultRecordAuth.label,
        actionRecommended: 'Practice standard cyber hygiene.',
      },
    },
    emergencyHelplineNeeded: false,
  };
}
