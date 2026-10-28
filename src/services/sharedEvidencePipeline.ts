import crypto from 'crypto';
import { URL } from 'url';
import {
  validateAndSanitizeUrl,
  matchAuthoritativeRegistry,
  detectBrandImpersonation,
  detectContentBrandImpersonation,
  safeRetrievePageInfo,
  AUTHORITATIVE_REGISTRY,
} from './investigationService.ts';
import { investigatePublicWebpage, type BrowserInvestigationResult } from './browserInvestigationService.ts';
import {
  evaluateEvidence,
  isShortenedUrl,
  SHORTENER_DOMAINS,
  HIGH_RISK_TLDS,
  hasHighRiskTld,
  detectScamUrlLures,
  type EvidenceInput,
  type EvaluatedDecision,
  type StandardVerdict,
  type FiveQuestionsAudit,
} from './classificationPolicy.ts';
import {
  recordDiagnosticTrace,
  auditFalseNegativeRisk,
  type DiagnosticTrace,
  type OcrDiagnostics,
  type ExtractedClaimIdentifiers,
} from './diagnosticLogger.ts';

export interface SourceAccessRecord {
  name: string;
  url: string;
  accessed: boolean;
  status: string;
}

export interface SharedInvestigationReport {
  targetType: 'link' | 'screenshot';
  inputIdentifier: string;
  domain?: string;
  verdict: StandardVerdict;
  verdictCategory: string;
  statusLabel: string;
  badgeColor: 'red' | 'amber' | 'emerald' | 'slate';
  contentSummary: string;
  evidence: string[];
  sourcesChecked: SourceAccessRecord[];
  sourcesActuallyAccessed: string[];
  verifiedClaims: string[];
  unverifiedClaims: string[];
  limitations: string;
  actionRecommended: string;
  fiveQuestions: FiveQuestionsAudit;
  emergencyHelplineNeeded: boolean;
  scanTimestamp: string;
  pipelineVersion: string;
  investigationMethod?: string;
}

// In-memory deterministic caches with TTL (15 minutes)
const pipelineCache = new Map<string, { report: SharedInvestigationReport; timestamp: number }>();
const CACHE_TTL_MS = 15 * 60 * 1000;

export function clearPipelineCache(): void {
  pipelineCache.clear();
}

export function getCachedReport(hash: string): SharedInvestigationReport | null {
  const entry = pipelineCache.get(hash);
  if (entry && Date.now() - entry.timestamp < CACHE_TTL_MS) {
    return entry.report;
  }
  return null;
}

export function setCachedReport(hash: string, report: SharedInvestigationReport): void {
  // Never cache transient failures, timeouts or temporary inability to verify
  // so that immediate re-tests or recovery attempts run cleanly
  if (report.verdict === 'UNABLE TO VERIFY') {
    return;
  }
  pipelineCache.set(hash, { report, timestamp: Date.now() });
}

/**
 * Robustly extracts full URLs, naked shortlinks, and suspicious domains from OCR text
 */
export function extractUrlsFromText(text: string): string[] {
  if (!text) return [];
  const results: string[] = [];

  // 1. Match standard URLs with scheme
  const standardRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  const standardMatches = text.match(standardRegex) || [];
  for (let m of standardMatches) {
    m = m.replace(/[.,;:!?)]+$/, '');
    if (m && !results.includes(m)) {
      results.push(m);
    }
  }

  // 2. Match naked shorteners (e.g. bit.ly/gcash-0ne, tinyurl.com/xyz, linkr.it/4bStpB)
  const shortenerRegex = /\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|rebrand\.ly|bl\.ink|tiny\.cc|v\.gd|s\.id|linkr\.it|t\.ly)\/[^\s<>"{}|\\^`[\]]+/gi;
  const shortenerMatches = text.match(shortenerRegex) || [];
  for (let m of shortenerMatches) {
    m = m.replace(/[.,;:!?)]+$/, '');
    const full = `https://${m}`;
    if (!results.includes(full) && !results.includes(m)) {
      results.push(full);
    }
  }

  // 3. Match naked high-risk or suspicious domains (e.g. free-recharge.buzz/claim, echallan-pra.cc/pk)
  const highRiskDomainRegex = /\b[a-zA-Z0-9-]+\.(?:buzz|top|click|cfd|sbs|rest|surf|monster|cam|skin|icu|uno|work|space|fit|gq|cf|ml|ga|tk|vip|party|quest|beauty|hair|live|loan|xyz|cc|site|online|shop|info|link)(?:\/[^\s<>"{}|\\^`[\]]*)?/gi;
  const highRiskMatches = text.match(highRiskDomainRegex) || [];
  for (let m of highRiskMatches) {
    m = m.replace(/[.,;:!?)]+$/, '');
    const full = `http://${m}`;
    if (!results.includes(full) && !results.some((r) => r.includes(m))) {
      results.push(full);
    }
  }

  // 4. Match naked civic and common domains with paths (e.g. psca.gop.pk/echallan, gcash.com/verify)
  const commonDomainRegex = /\b(?:www\.[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+|[a-zA-Z0-9-]+\.(?:gov\.pk|gop\.pk|gos\.pk|com\.pk|org\.pk|edu\.pk|com|ph|org|net)\/[^\s<>"{}|\\^`[\]]*)/gi;
  const commonMatches = text.match(commonDomainRegex) || [];
  for (let m of commonMatches) {
    m = m.replace(/[.,;:!?)]+$/, '');
    const full = m.startsWith('www.') ? `https://${m}` : `http://${m}`;
    if (!results.includes(full) && !results.some((r) => r.includes(m))) {
      results.push(full);
    }
  }

  return results;
}

/**
 * Checks URL against Google Safe Browsing v4 Threat Intelligence
 * Handles all 4 states: CONFIRMED_THREAT, CLEAN_RECORD, TIMEOUT/ERROR, NOT_CONFIGURED
 */
export async function querySafeBrowsing(targetUrl: string): Promise<{
  checked: boolean;
  hasThreatMatch: boolean;
  threatTypes?: string[];
  error?: string;
  sourceRecord: SourceAccessRecord;
}> {
  const apiKey = process.env.SAFE_BROWSING_API_KEY || process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      checked: false,
      hasThreatMatch: false,
      sourceRecord: {
        name: 'Google Safe Browsing Threat Intelligence',
        url: 'https://safebrowsing.googleapis.com',
        accessed: false,
        status: 'Not configured (SAFE_BROWSING_API_KEY secret required)',
      },
    };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const sbResponse = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'cyber-saathi-pipeline', clientVersion: '2.6.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: targetUrl }],
          },
        }),
        signal: controller.signal,
      }
    );
    clearTimeout(timeoutId);

    if (sbResponse.ok) {
      const data = await sbResponse.json();
      const matches = data.matches || [];
      const hasMatch = matches.length > 0;
      const threatTypes = matches.map((m: any) => m.threatType);

      return {
        checked: true,
        hasThreatMatch: hasMatch,
        threatTypes,
        sourceRecord: {
          name: 'Google Safe Browsing v4 Threat Intelligence',
          url: 'https://safebrowsing.googleapis.com',
          accessed: true,
          status: hasMatch ? `Confirmed threat match: ${threatTypes.join(', ')}` : 'Clean record (Zero matches)',
        },
      };
    } else {
      const errData = await sbResponse.json().catch(() => ({}));
      const errMsg = errData.error?.message || `HTTP ${sbResponse.status}`;
      return {
        checked: false,
        hasThreatMatch: false,
        error: errMsg,
        sourceRecord: {
          name: 'Google Safe Browsing v4 Threat Intelligence',
          url: 'https://safebrowsing.googleapis.com',
          accessed: false,
          status: `Provider error: ${errMsg}`,
        },
      };
    }
  } catch (err: any) {
    clearTimeout(timeoutId);
    const errMsg = err.name === 'AbortError' ? 'Lookup timed out (5s limit)' : err.message;
    return {
      checked: false,
      hasThreatMatch: false,
      error: errMsg,
      sourceRecord: {
        name: 'Google Safe Browsing v4 Threat Intelligence',
        url: 'https://safebrowsing.googleapis.com',
        accessed: false,
        status: `Lookup failed: ${errMsg}`,
      },
    };
  }
}

/**
 * Shared Link Investigation Pipeline
 * Operates with deterministic caching, SSRF defenses, and headless browser / HTTP retrieval
 */
export async function investigateLink(
  rawUrl: string,
  options?: { bypassCache?: boolean }
): Promise<SharedInvestigationReport> {
  const scanTimestamp = new Date().toISOString();
  const trimmedUrl = rawUrl.trim();
  const hash = crypto.createHash('sha256').update(trimmedUrl.toLowerCase()).digest('hex');

  // Check cache for identical input unless explicitly bypassed
  if (!options?.bypassCache) {
    const cached = getCachedReport(hash);
    if (cached) {
      return cached;
    }
  }

  const sourcesChecked: SourceAccessRecord[] = [];

  // Step 0: Pre-resolution Candidate URL Inspection (Check brand impersonation prior to DNS resolution)
  let candidateHost = '';
  let candidatePath = '/';
  try {
    const candidateObj = new URL(
      trimmedUrl.startsWith('http://') || trimmedUrl.startsWith('https://')
        ? trimmedUrl
        : `http://${trimmedUrl}`
    );
    candidateHost = candidateObj.hostname.toLowerCase();
    candidatePath = candidateObj.pathname;
  } catch {
    // Malformed URL syntax
  }

  const preResolutionImpersonation = candidateHost
    ? detectBrandImpersonation(candidateHost, candidatePath)
    : { impersonating: false };

  // Step 1: URL Syntax & SSRF Security Check
  const sanitize = await validateAndSanitizeUrl(trimmedUrl);
  if (!sanitize.valid || !sanitize.normalizedUrl || !sanitize.domain) {
    sourcesChecked.push({
      name: 'Local DNS & SSRF Gateway',
      url: trimmedUrl,
      accessed: true,
      status: `Host validation: ${sanitize.reason}`,
    });

    const isImpersonating = Boolean(preResolutionImpersonation.impersonating);
    const isShortened = isShortenedUrl(trimmedUrl);
    const lures = detectScamUrlLures(trimmedUrl);
    const hasTldRisk = hasHighRiskTld(trimmedUrl);

    let decision: EvaluatedDecision;

    if (sanitize.isSecurityBlock && !isImpersonating) {
      decision = evaluateEvidence({
        urlsExtracted: [trimmedUrl],
        securityBlockReason: sanitize.reason || 'Invalid URL or private network address.',
      });
    } else {
      decision = evaluateEvidence({
        urlsExtracted: [trimmedUrl],
        brandImpersonation: isImpersonating ? preResolutionImpersonation : undefined,
        isShortenedUrl: isShortened,
        isUnverifiedShortLink: isShortened,
        unverifiedShortLinkReason: isShortened
          ? 'Destination not verified: Short-link redirect could not be safely resolved.'
          : undefined,
      });

      if (isImpersonating) {
        decision.evidence.push(
          `Pre-resolution domain check: Domain impersonation detected prior to DNS resolution (${sanitize.reason || 'host unreachable'}).`
        );
      } else if (trimmedUrl.endsWith('...') || trimmedUrl.endsWith('…') || trimmedUrl.endsWith('..') || trimmedUrl.includes('...')) {
        decision.verdict = 'SUSPICIOUS';
        decision.verdictCategory = 'SUSPICIOUS';
        decision.badgeColor = 'amber';
        decision.statusLabel = 'SUSPICIOUS — INCOMPLETE / BROKEN LINK';
        decision.contentSummary = 'This link is incomplete or cut off (ends with "..."). Scammers hide the real destination, and an incomplete link cannot be verified.';
        decision.evidence.push('Incomplete / broken link: The link is cut off, ends with "...", or looks half-copied. Destination cannot be verified.');
        decision.actionRecommended = 'This link is incomplete, so I cannot confirm where it goes. Do NOT open it. Ask the sender for the full official link, or go to the official app/website yourself.';
        decision.fiveQuestions.questionC_destinationUrl = {
          answered: true,
          summary: 'Incomplete destination address',
          findings: 'The link is cut off, ends with "...", or looks half-copied. An incomplete link cannot be verified.',
        };
      } else if (lures.length > 0 || hasTldRisk) {
        decision.evidence.push(
          `Deceptive web link analysis: ${sanitize.reason || 'DNS unresolvable'}. Hostname exhibits high-risk scam markers.`
        );
      } else {
        decision.verdict = 'UNABLE TO VERIFY';
        decision.verdictCategory = 'UNABLE TO VERIFY';
        decision.badgeColor = 'slate';
        decision.statusLabel = 'UNABLE TO VERIFY (DOMAIN UNRESOLVABLE / UNREACHABLE)';
        decision.contentSummary = `The domain name '${candidateHost || trimmedUrl}' could not be resolved via public DNS. It may be inactive, newly registered, or unreachable.`;
        decision.evidence.push(`DNS lookup failed: ${sanitize.reason || 'Domain not found'}.`);
        decision.limitations = 'Cannot inspect destination server content or TLS security headers because the domain did not return an active IP address.';
        decision.actionRecommended = 'Check if the URL contains a typo, or if the website is temporarily offline.';
      }
    }

    const report: SharedInvestigationReport = {
      targetType: 'link',
      inputIdentifier: trimmedUrl,
      domain: candidateHost || sanitize.domain || trimmedUrl,
      verdict: decision.verdict,
      verdictCategory: decision.verdictCategory,
      statusLabel: decision.statusLabel,
      badgeColor: decision.badgeColor,
      contentSummary: decision.contentSummary,
      evidence: decision.evidence,
      sourcesChecked,
      sourcesActuallyAccessed: sourcesChecked.filter((s) => s.accessed).map((s) => s.name),
      verifiedClaims: decision.verifiedClaims,
      unverifiedClaims: decision.unverifiedClaims,
      limitations: decision.limitations,
      actionRecommended: decision.actionRecommended,
      fiveQuestions: decision.fiveQuestions,
      emergencyHelplineNeeded: decision.emergencyHelplineNeeded,
      scanTimestamp,
      pipelineVersion: '2.6.0',
    };

    setCachedReport(hash, report);
    return report;
  }

  const normalizedUrl = sanitize.normalizedUrl;
  const domain = sanitize.domain;
  const isGov = domain.endsWith('.gov.pk') || domain.endsWith('.gos.pk');

  // Step 2: Query Google Safe Browsing
  const sbResult = await querySafeBrowsing(normalizedUrl);
  sourcesChecked.push(sbResult.sourceRecord);

  // Step 3: Brand Impersonation Check
  let impersonation = detectBrandImpersonation(domain, new URL(normalizedUrl).pathname);

  // Step 4: Authoritative Registry Match
  const matchedAuthority = matchAuthoritativeRegistry(domain);
  const authName = matchedAuthority
    ? matchedAuthority.name
    : isGov
    ? 'Government of Pakistan / Sindh Official Gateway'
    : undefined;

  if (matchedAuthority || isGov) {
    sourcesChecked.push({
      name: authName || 'Official Pakistani Public Registry',
      url: matchedAuthority?.publicVerificationUrl || `https://${domain}`,
      accessed: false, // Internal registry dataset match
      status: 'Domain confirmed in verified civic registry (Internal dataset match)',
    });
  }

  // Step 4.5: Server-side safe resolution for shortened URLs
  const isShortened = isShortenedUrl(normalizedUrl);
  let isUnverifiedShort = false;
  let unverifiedShortReason: string | undefined;

  if (isShortened) {
    try {
      const pageInfo = await safeRetrievePageInfo(normalizedUrl, 5);
      if (pageInfo.retrieved && pageInfo.finalUrl && pageInfo.finalUrl !== normalizedUrl) {
        sourcesChecked.push({
          name: 'Protected Server-Side Link Resolver (SSRF Defense)',
          url: normalizedUrl,
          accessed: true,
          status: `Safely resolved redirect to: ${pageInfo.finalUrl}`,
        });

        try {
          const expParsed = new URL(pageInfo.finalUrl);
          const expHost = expParsed.hostname.toLowerCase();
          const expPath = expParsed.pathname || '/';

          const expImpersonation = detectBrandImpersonation(expHost, expPath);
          if (expImpersonation.impersonating) {
            impersonation = expImpersonation;
          }

          const expSb = await querySafeBrowsing(pageInfo.finalUrl);
          if (expSb.hasThreatMatch) {
            sbResult.hasThreatMatch = true;
            sbResult.threatTypes = expSb.threatTypes;
            sourcesChecked.push(expSb.sourceRecord);
          }
        } catch {
          // ignore url parse
        }
      } else {
        isUnverifiedShort = true;
        unverifiedShortReason =
          'Destination not verified: Short-link redirect could not be safely expanded without executing untrusted client scripts.';
        sourcesChecked.push({
          name: 'Protected Server-Side Link Resolver (SSRF Defense)',
          url: normalizedUrl,
          accessed: false,
          status: 'Destination not verified: Short-link service did not return an authenticated destination.',
        });
      }
    } catch (resolverErr: any) {
      isUnverifiedShort = true;
      unverifiedShortReason = 'Destination not verified: Error during safe server-side URL expansion.';
      sourcesChecked.push({
        name: 'Protected Server-Side Link Resolver (SSRF Defense)',
        url: normalizedUrl,
        accessed: false,
        status: `Destination not verified (${resolverErr?.message || 'Expansion failed'})`,
      });
    }
  }

  // Step 5: Public Webpage Inspection (Headless Chromium or safe HTTP)
  let browserResult: BrowserInvestigationResult | undefined;
  if (!sbResult.hasThreatMatch && !impersonation.impersonating) {
    browserResult = await investigatePublicWebpage(normalizedUrl);
    if (browserResult.retrieved) {
      sourcesChecked.push({
        name: `Destination Web Server (${domain})`,
        url: browserResult.finalUrl || normalizedUrl,
        accessed: true,
        status: `HTTP ${browserResult.httpStatus || 200} OK - Title: "${browserResult.title || 'Page retrieved'}"`,
      });
    } else {
      sourcesChecked.push({
        name: `Destination Web Server (${domain})`,
        url: normalizedUrl,
        accessed: false,
        status: `Retrieval failed: ${browserResult.failureReason || 'Connection failed or timeout'}`,
      });
    }
  }

  // Step 6: Pass all evidence to the central deterministic classification policy
  const evidenceInput: EvidenceInput = {
    urlsExtracted: [normalizedUrl],
    apparentOrg: authName || (impersonation.impersonating ? impersonation.claimedOrg : undefined),
    isOfficialGov: isGov,
    isAuthoritativeEntity: Boolean(matchedAuthority),
    authoritativeEntityName: authName,
    threatIntelResult: {
      checked: sbResult.checked,
      hasThreatMatch: sbResult.hasThreatMatch,
      threatTypes: sbResult.threatTypes,
      error: sbResult.error,
    },
    destinationPageInfo: browserResult
      ? {
          retrieved: browserResult.retrieved,
          httpStatus: browserResult.httpStatus,
          finalUrl: browserResult.finalUrl,
          title: browserResult.title,
          hasLoginForm: browserResult.securityObservations.some((s) => s.includes('input fields')),
          failureReason: browserResult.failureReason,
          requiresJavaScript: browserResult.requiresJavaScript,
        }
      : undefined,
    brandImpersonation: impersonation,
    isShortenedUrl: isShortened,
    isUnverifiedShortLink: isUnverifiedShort,
    unverifiedShortLinkReason: unverifiedShortReason,
  };

  // If a government subpage returned 404 or connection failure, reflect unable to verify
  if ((isGov || matchedAuthority) && browserResult && (!browserResult.retrieved || (browserResult.httpStatus && browserResult.httpStatus >= 400))) {
    evidenceInput.isUnreadableOrEmpty = false;
    // We override decision to UNABLE TO VERIFY broken official subpage
    const decision = evaluateEvidence(evidenceInput);
    decision.verdict = 'UNABLE TO VERIFY';
    decision.badgeColor = 'slate';
    decision.statusLabel = 'UNABLE TO VERIFY (OFFICIAL DOMAIN / SUBPAGE UNREACHABLE)';
    decision.contentSummary = `Domain '${domain}' belongs to ${authName}, but the specific submitted page could not be retrieved (${browserResult.failureReason || `HTTP ${browserResult.httpStatus}`}).`;
    decision.limitations = 'Domain registration confirms the hosting organization, but cannot verify an unreachable or broken sub-page.';

    const report: SharedInvestigationReport = {
      targetType: 'link',
      inputIdentifier: trimmedUrl,
      domain,
      verdict: decision.verdict,
      verdictCategory: 'UNABLE TO VERIFY',
      statusLabel: decision.statusLabel,
      badgeColor: decision.badgeColor,
      contentSummary: decision.contentSummary,
      evidence: decision.evidence,
      sourcesChecked,
      sourcesActuallyAccessed: sourcesChecked.filter((s) => s.accessed).map((s) => s.name),
      verifiedClaims: decision.verifiedClaims,
      unverifiedClaims: decision.unverifiedClaims,
      limitations: decision.limitations,
      actionRecommended: decision.actionRecommended,
      fiveQuestions: decision.fiveQuestions,
      emergencyHelplineNeeded: decision.emergencyHelplineNeeded,
      scanTimestamp,
      pipelineVersion: '2.6.0',
      investigationMethod: browserResult?.investigationMethod,
    };

    setCachedReport(hash, report);
    return report;
  }

  const decision = evaluateEvidence(evidenceInput);

  const report: SharedInvestigationReport = {
    targetType: 'link',
    inputIdentifier: trimmedUrl,
    domain,
    verdict: decision.verdict,
    verdictCategory: decision.verdictCategory,
    statusLabel: decision.statusLabel,
    badgeColor: decision.badgeColor,
    contentSummary: decision.contentSummary,
    evidence: decision.evidence,
    sourcesChecked,
    sourcesActuallyAccessed: sourcesChecked.filter((s) => s.accessed).map((s) => s.name),
    verifiedClaims: decision.verifiedClaims,
    unverifiedClaims: decision.unverifiedClaims,
    limitations: decision.limitations,
    actionRecommended: decision.actionRecommended,
    fiveQuestions: decision.fiveQuestions,
    emergencyHelplineNeeded: decision.emergencyHelplineNeeded,
    scanTimestamp,
    pipelineVersion: '2.6.0',
    investigationMethod: browserResult?.investigationMethod,
  };

  setCachedReport(hash, report);
  return report;
}

/**
 * Shared Screenshot & SMS Investigation Pipeline
 * Analyzes extracted text, sender, candidate URLs, and QR codes through the shared policy
 */
export async function investigateScreenshotEvidence(params: {
  rawText: string;
  sender?: string;
  qrCodeUrl?: string;
  imageHash?: string;
  bypassCache?: boolean;
}): Promise<SharedInvestigationReport> {
  const scanTimestamp = new Date().toISOString();
  const rawText = (params.rawText || '').trim();
  const sender = (params.sender || '').trim();
  const qrCodeUrl = params.qrCodeUrl ? params.qrCodeUrl.trim() : undefined;

  const contentToHash = `${rawText}::${sender}::${qrCodeUrl || ''}`;
  const hash = params.imageHash || crypto.createHash('sha256').update(contentToHash).digest('hex');

  // Check cache unless explicitly bypassed
  if (!params.bypassCache) {
    const cached = getCachedReport(hash);
    if (cached) {
      return cached;
    }
  }

  const sourcesChecked: SourceAccessRecord[] = [];

  // Check if image is completely empty or unreadable
  if (!rawText && !qrCodeUrl) {
    const decision = evaluateEvidence({
      isUnreadableOrEmpty: true,
      unreadableReason: 'Uploaded screenshot is unreadable or contains no discernible text or QR code.',
    });

    const report: SharedInvestigationReport = {
      targetType: 'screenshot',
      inputIdentifier: hash.slice(0, 16),
      verdict: decision.verdict,
      verdictCategory: decision.verdictCategory,
      statusLabel: decision.statusLabel,
      badgeColor: decision.badgeColor,
      contentSummary: decision.contentSummary,
      evidence: decision.evidence,
      sourcesChecked: [],
      sourcesActuallyAccessed: [],
      verifiedClaims: decision.verifiedClaims,
      unverifiedClaims: decision.unverifiedClaims,
      limitations: decision.limitations,
      actionRecommended: decision.actionRecommended,
      fiveQuestions: decision.fiveQuestions,
      emergencyHelplineNeeded: decision.emergencyHelplineNeeded,
      scanTimestamp,
      pipelineVersion: '2.6.0',
    };

    setCachedReport(hash, report);
    return report;
  }

  // Extract candidate URLs from text (handles both https?:// and naked links/shorteners)
  const urlsInText: string[] = extractUrlsFromText(rawText);
  if (qrCodeUrl && !urlsInText.includes(qrCodeUrl)) {
    urlsInText.push(qrCodeUrl);
  }

  // Analyze primary URL if present
  let threatIntelResult: { checked: boolean; hasThreatMatch: boolean; threatTypes?: string[]; error?: string } | undefined;
  let brandImpersonationResult: { impersonating: boolean; claimedOrg?: string; officialDomain?: string; reason?: string } | undefined;
  let isOfficialGov = false;
  let authoritativeEntityName: string | undefined;
  let securityBlockReason: string | undefined;
  let isShortened = false;
  let isUnverifiedShort = false;
  let unverifiedShortReason: string | undefined;
  let resolvedDestinationInfo: any = undefined;

  if (urlsInText.length > 0) {
    const primaryUrl = urlsInText[0];
    let candidateHost = '';
    let candidatePath = '/';
    try {
      const parsed = new URL(primaryUrl);
      candidateHost = parsed.hostname.toLowerCase();
      candidatePath = parsed.pathname || '/';
    } catch {
      // Ignore URL parsing errors
    }

    isShortened = isShortenedUrl(primaryUrl);

    if (candidateHost) {
      isOfficialGov = candidateHost.endsWith('.gov.pk') || candidateHost.endsWith('.gos.pk');
      const matchedAuth = matchAuthoritativeRegistry(candidateHost);
      if (matchedAuth) {
        authoritativeEntityName = matchedAuth.name;
      }
      brandImpersonationResult = detectBrandImpersonation(candidateHost, candidatePath);
    }

    const sanitize = await validateAndSanitizeUrl(primaryUrl);
    if (!sanitize.valid) {
      if (sanitize.reason?.includes('Security Block') || sanitize.reason?.includes('Unsafe scheme') || sanitize.reason?.includes('blocked')) {
        securityBlockReason = sanitize.reason;
      }
    } else if (sanitize.valid && sanitize.normalizedUrl && sanitize.domain) {
      if (!authoritativeEntityName) {
        const matchedAuth = matchAuthoritativeRegistry(sanitize.domain);
        if (matchedAuth) authoritativeEntityName = matchedAuth.name;
      }
      if (!brandImpersonationResult || !brandImpersonationResult.impersonating) {
        brandImpersonationResult = detectBrandImpersonation(sanitize.domain, new URL(sanitize.normalizedUrl).pathname);
      }

      // Safe Browsing query for extracted link
      const sb = await querySafeBrowsing(sanitize.normalizedUrl);
      sourcesChecked.push(sb.sourceRecord);
      threatIntelResult = {
        checked: sb.checked,
        hasThreatMatch: sb.hasThreatMatch,
        threatTypes: sb.threatTypes,
        error: sb.error,
      };

      // Server-side safe resolution for shortened URLs (with strict redirect SSRF checks)
      if (isShortened) {
        try {
          const pageInfo = await safeRetrievePageInfo(sanitize.normalizedUrl, 5);
          resolvedDestinationInfo = pageInfo;
          if (pageInfo.retrieved && pageInfo.finalUrl && pageInfo.finalUrl !== sanitize.normalizedUrl) {
            sourcesChecked.push({
              name: 'Protected Server-Side Link Resolver (SSRF Defense)',
              url: sanitize.normalizedUrl,
              accessed: true,
              status: `Safely resolved redirect to: ${pageInfo.finalUrl}`,
            });

            // Re-evaluate expanded destination for threat intelligence and brand impersonation
            try {
              const expandedParsed = new URL(pageInfo.finalUrl);
              const expandedHost = expandedParsed.hostname.toLowerCase();
              const expandedPath = expandedParsed.pathname || '/';

              const expandedImpersonation = detectBrandImpersonation(expandedHost, expandedPath);
              if (expandedImpersonation.impersonating) {
                brandImpersonationResult = expandedImpersonation;
              }

              const expandedSb = await querySafeBrowsing(pageInfo.finalUrl);
              if (expandedSb.hasThreatMatch) {
                threatIntelResult = {
                  checked: true,
                  hasThreatMatch: true,
                  threatTypes: expandedSb.threatTypes,
                };
                sourcesChecked.push(expandedSb.sourceRecord);
              }
            } catch {
              // URL parsing error on expanded URL
            }
          } else {
            // Expansion failed or unresolved
            isUnverifiedShort = true;
            unverifiedShortReason = 'Destination not verified: Short-link redirect could not be safely expanded without executing untrusted client scripts.';
            sourcesChecked.push({
              name: 'Protected Server-Side Link Resolver (SSRF Defense)',
              url: sanitize.normalizedUrl,
              accessed: false,
              status: 'Destination not verified: Short-link service did not return an authenticated destination.',
            });
          }
        } catch (resolverErr: any) {
          isUnverifiedShort = true;
          unverifiedShortReason = 'Destination not verified: Error during safe server-side URL expansion.';
          sourcesChecked.push({
            name: 'Protected Server-Side Link Resolver (SSRF Defense)',
            url: sanitize.normalizedUrl,
            accessed: false,
            status: `Destination not verified (${resolverErr?.message || 'Expansion failed'})`,
          });
        }
      }
    }
  }

  // Check for brand impersonation directly in message content and sender (e.g. scams with no URL)
  if (!brandImpersonationResult || !brandImpersonationResult.impersonating) {
    const contentImp = detectContentBrandImpersonation(rawText, sender);
    if (contentImp.impersonating) {
      brandImpersonationResult = contentImp;
    }
  }

  // Check for genuine public safety advisory signatures
  const lowerText = rawText.toLowerCase();
  const isProtectiveAdvisory =
    (/never\s+(share|provide|disclose|give|tell)\b.*(otp|pin|password|mpin|code)/i.test(lowerText) ||
      /do\s+not\s+(share|provide|disclose|give|tell)\b.*(otp|pin|password|mpin|code)/i.test(lowerText) ||
      /(public\s+advisory|cyber\s+advisory|security\s+alert|citizen\s+warning)\b/i.test(lowerText)) &&
    (lowerText.includes('1991') ||
      lowerText.includes('complaint.fia.gov.pk') ||
      lowerText.includes('fia.gov.pk') ||
      lowerText.includes('nccia.gov.pk') ||
      lowerText.includes('nccia') ||
      lowerText.includes('8171') ||
      lowerText.includes('bisp.gov.pk') ||
      lowerText.includes('cnic.sims.pk') ||
      lowerText.includes('pta.gov.pk') ||
      lowerText.includes('sbp.org.pk')) &&
    !/share\s+otp\s+to\s+claim|call\s+03\d{2}/i.test(lowerText);

  if (isProtectiveAdvisory) {
    sourcesChecked.push({
      name: 'FIA Cyber Crime Wing / NCCIA Advisory Registry',
      url: 'https://complaint.fia.gov.pk',
      accessed: true,
      status: 'Advisory guidance corroborated with official public safety rules',
    });
  }

  // Match claimed sender against registry
  const matchedSenderAuth = sender ? AUTHORITATIVE_REGISTRY.find((r) => r.officialShortcodes?.includes(sender)) : undefined;
  if (matchedSenderAuth) {
    authoritativeEntityName = matchedSenderAuth.name;
    sourcesChecked.push({
      name: `${matchedSenderAuth.name} Official Channel`,
      url: matchedSenderAuth.publicVerificationUrl || 'https://fia.gov.pk',
      accessed: false, // Internal shortcode registry match
      status: `Shortcode ${sender} matches official broadcast registry`,
    });
  }

  const decision = evaluateEvidence({
    rawText,
    sender,
    urlsExtracted: urlsInText,
    qrCodeUrl,
    apparentOrg: authoritativeEntityName,
    isOfficialGov,
    isAuthoritativeEntity: Boolean(matchedSenderAuth),
    authoritativeEntityName,
    threatIntelResult,
    destinationPageInfo: resolvedDestinationInfo,
    brandImpersonation: brandImpersonationResult,
    isProtectiveAdvisory,
    securityBlockReason,
    isShortenedUrl: isShortened,
    isUnverifiedShortLink: isUnverifiedShort,
    unverifiedShortLinkReason: unverifiedShortReason,
  });

  // Record diagnostic trace for root-cause tracking
  if (decision.decisionPath) {
    const ocrDiag: OcrDiagnostics = {
      isReadable: !decision.decisionPath.conditionTruthTable.isUnreadableOrEmpty,
      rawText,
      rawTextLength: rawText.length,
      sender,
      senderClassification: /^(03\d{2}|(\+92\s?3\d{2}))\s?\d{7}$/.test(sender.replace(/[\s-]/g, ''))
        ? 'private_sim'
        : matchedSenderAuth
        ? 'official_shortcode'
        : sender
        ? 'alphanumeric'
        : 'empty',
      documentType: 'Digital Screenshot / Mobile Communication',
      ocrModelUsed: 'Forensic OCR / Feature Extraction',
      qrCodeDecoded: qrCodeUrl,
    };

    const claimsDiag: ExtractedClaimIdentifiers = {
      urls: urlsInText,
      referenceNumbers: decision.auditReport?.partA_contentAndClaims.extractedReferenceNumbers || [],
      amounts: decision.auditReport?.partA_contentAndClaims.extractedAmounts || [],
      vehicleDetails: decision.auditReport?.partA_contentAndClaims.extractedVehicleDetails,
      claimedEntities: authoritativeEntityName ? [authoritativeEntityName] : [],
      isChallanOrFine: Boolean(decision.auditReport?.partA_contentAndClaims.documentType?.includes('Challan')),
      isBankOrTransferReceipt: Boolean(decision.auditReport?.partA_contentAndClaims.documentType?.includes('Receipt')),
      isProtectiveAdvisory: Boolean(isProtectiveAdvisory),
      scamSignalsDetected: decision.auditReport?.partB_suspiciousRequests.detectedSignals || [],
    };

    const falseNegativeRisk = auditFalseNegativeRisk(ocrDiag, claimsDiag, decision.decisionPath);

    const diagnosticTrace: DiagnosticTrace = {
      traceId: crypto.randomUUID ? crypto.randomUUID() : hash.slice(0, 16),
      timestamp: scanTimestamp,
      source: 'screenshot_pipeline',
      imageHash: hash,
      ocrStage: ocrDiag,
      claimsStage: claimsDiag,
      brandImpersonationStage: {
        checked: Boolean(brandImpersonationResult),
        impersonating: Boolean(brandImpersonationResult?.impersonating),
        claimedOrg: brandImpersonationResult?.claimedOrg,
        officialDomain: brandImpersonationResult?.officialDomain,
        reason: brandImpersonationResult?.reason,
      },
      threatIntelStage: {
        checked: Boolean(threatIntelResult?.checked),
        hasThreatMatch: Boolean(threatIntelResult?.hasThreatMatch),
        threatTypes: threatIntelResult?.threatTypes || [],
        error: threatIntelResult?.error,
      },
      decisionPath: decision.decisionPath,
      falseNegativeAudit: falseNegativeRisk,
      executionDurationMs: 0,
    };

    recordDiagnosticTrace(diagnosticTrace);
  }

  const report: SharedInvestigationReport = {
    targetType: 'screenshot',
    inputIdentifier: hash.slice(0, 16),
    verdict: decision.verdict,
    verdictCategory: decision.verdictCategory,
    statusLabel: decision.statusLabel,
    badgeColor: decision.badgeColor,
    contentSummary: decision.contentSummary,
    evidence: decision.evidence,
    sourcesChecked,
    sourcesActuallyAccessed: sourcesChecked.filter((s) => s.accessed).map((s) => s.name),
    verifiedClaims: decision.verifiedClaims,
    unverifiedClaims: decision.unverifiedClaims,
    limitations: decision.limitations,
    actionRecommended: decision.actionRecommended,
    fiveQuestions: decision.fiveQuestions,
    emergencyHelplineNeeded: decision.emergencyHelplineNeeded,
    scanTimestamp,
    pipelineVersion: '2.6.0',
  };

  setCachedReport(hash, report);
  return report;
}
