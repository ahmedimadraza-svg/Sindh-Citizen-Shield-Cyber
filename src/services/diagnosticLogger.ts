/**
 * Diagnostic Logging Utility for SIN Cyber Saathi
 * 
 * Captures intermediate OCR extractions, extracted claim identifiers,
 * truth-table boolean flags, and the exact decision path of classificationPolicy.ts
 * to isolate the root cause of false-negative (or false-safe) verdicts.
 */

export interface OcrDiagnostics {
  isReadable: boolean;
  unreadableReason?: string;
  rawText: string;
  rawTextLength: number;
  sender: string;
  senderClassification: 'private_sim' | 'official_shortcode' | 'alphanumeric' | 'unknown' | 'empty';
  documentType: string;
  ocrModelUsed: string;
  qrCodeDecoded?: string;
}

export interface ExtractedClaimIdentifiers {
  urls: string[];
  referenceNumbers: string[];
  amounts: string[];
  vehicleDetails?: string;
  claimedEntities: string[];
  isChallanOrFine: boolean;
  isBankOrTransferReceipt: boolean;
  isProtectiveAdvisory: boolean;
  scamSignalsDetected: string[];
}

export interface DecisionPathLog {
  evaluatedRule: string;
  ruleClause: string;
  ruleRationale: string;
  conditionTruthTable: {
    hasConfirmedThreatIntel: boolean;
    hasBrandImpersonation: boolean;
    hasActiveFraudSignals: boolean;
    demandsOtp: boolean;
    isNegatedOtp: boolean;
    demandsAdvanceFeeOrLottery: boolean;
    extortionThreat: boolean;
    demandsPrivateChallanPayment: boolean;
    isPrivateSimSender: boolean;
    isDeceptiveSubdomain: boolean;
    isHomoglyph: boolean;
    isSuspiciousUrl: boolean;
    hasUnverifiedLinkInPrivateSms: boolean;
    hasSecurityBlock: boolean;
    isUnreadableOrEmpty: boolean;
    hasUnexpectedGrantClaim?: boolean;
    hasAccountActionViaLink?: boolean;
    isShortenedUrl?: boolean;
    isUnverifiedShortLink?: boolean;
  };
  verdict: string;
  verdictCategory: string;
  badgeColor: string;
  statusLabel: string;
  evidenceItemsCount: number;
}

export interface FalseNegativeRiskAudit {
  hasRiskOfFalseNegative: boolean;
  riskSeverity: 'none' | 'low' | 'medium' | 'high';
  detectedRiskFactors: string[];
  investigatorNotice?: string;
}

export interface DiagnosticTrace {
  traceId: string;
  timestamp: string;
  source: 'screenshot_pipeline' | 'direct_text_pipeline' | 'link_pipeline';
  imageHash?: string;
  ocrStage: OcrDiagnostics;
  claimsStage: ExtractedClaimIdentifiers;
  brandImpersonationStage?: {
    checked: boolean;
    impersonating: boolean;
    claimedOrg?: string;
    officialDomain?: string;
    reason?: string;
  };
  threatIntelStage?: {
    checked: boolean;
    hasThreatMatch: boolean;
    threatTypes: string[];
    error?: string;
  };
  decisionPath: DecisionPathLog;
  falseNegativeAudit: FalseNegativeRiskAudit;
  executionDurationMs: number;
}

// Rolling in-memory ring buffer (retains up to 100 recent diagnostic traces)
const MAX_TRACES = 100;
const traceBuffer: DiagnosticTrace[] = [];

/**
 * Analyzes whether a non-threat or suspicious verdict carries false-negative risk.
 */
export function auditFalseNegativeRisk(
  ocr: OcrDiagnostics,
  claims: ExtractedClaimIdentifiers,
  decision: DecisionPathLog
): FalseNegativeRiskAudit {
  const riskFactors: string[] = [];

  // Check 1: Non-threat verdict despite detected scam signals
  if (decision.verdict === 'NO KNOWN THREAT FOUND' && claims.scamSignalsDetected.length > 0) {
    riskFactors.push(
      `Verdict is NO KNOWN THREAT FOUND but scam signals were extracted: ${claims.scamSignalsDetected.join('; ')}`
    );
  }

  // Check 2: Unsolicited financial claims or cash prizes without verified authority
  if (
    decision.verdict === 'NO KNOWN THREAT FOUND' &&
    claims.amounts.length > 0 &&
    ocr.senderClassification === 'private_sim'
  ) {
    riskFactors.push(
      `Financial amounts (${claims.amounts.join(', ')}) communicated from an unverified private SIM (${ocr.sender}).`
    );
  }

  // Check 3: Reference to sensitive authentication (OTP/PIN/password) without confirmed threat
  const lowerText = ocr.rawText.toLowerCase();
  const mentionsAuthSecrets = /\b(otp|mpin|pin\s+code|password|passcode)\b/i.test(lowerText);
  if (
    decision.verdict === 'NO KNOWN THREAT FOUND' &&
    mentionsAuthSecrets &&
    !claims.isProtectiveAdvisory
  ) {
    riskFactors.push(
      'Message contains authentication keywords (OTP/PIN/Password) but was not marked as a confirmed threat or protective advisory.'
    );
  }

  // Check 4: Unofficial link present in an alleged government or bank notification
  if (
    decision.verdict === 'NO KNOWN THREAT FOUND' &&
    claims.urls.length > 0 &&
    claims.claimedEntities.length > 0
  ) {
    const hasGovDomain = claims.urls.some((u) => u.includes('.gov.pk') || u.includes('.gos.pk') || u.includes('.gop.pk'));
    if (!hasGovDomain) {
      riskFactors.push(
        `Communication claims to represent ${claims.claimedEntities.join(', ')} but links to an unofficial domain (${claims.urls[0]}).`
      );
    }
  }

  // Check 5: Challan notice instructing payment outside 1Link / 1Bill
  if (
    decision.verdict === 'NO KNOWN THREAT FOUND' &&
    claims.isChallanOrFine &&
    (ocr.senderClassification === 'private_sim' || /jazzcash|easypaisa/i.test(lowerText))
  ) {
    riskFactors.push(
      'Traffic challan notice associated with a private SIM or mobile wallet rather than official PSID rails.'
    );
  }

  // Check 6: Unexpected government cash assistance or social grant claims in non-threat verdict
  if (
    decision.verdict === 'NO KNOWN THREAT FOUND' &&
    claims.scamSignalsDetected.some(
      (s) => s.includes('cash assistance') || s.includes('grant') || s.includes('Ayuda')
    )
  ) {
    riskFactors.push(
      'Unexpected government cash assistance / Ayuda claim was classified as NO KNOWN THREAT FOUND.'
    );
  }

  // Check 7: Shortened URL hiding destination or account action via link in non-threat verdict
  if (
    decision.verdict === 'NO KNOWN THREAT FOUND' &&
    (claims.scamSignalsDetected.some((s) => s.includes('Shortened URL') || s.includes('check balance')) ||
      claims.urls.some((u) => /bit\.ly|tinyurl|t\.co|cutt\.ly|is\.gd|rb\.gy/i.test(u)))
  ) {
    riskFactors.push(
      'Shortened URL or account action demand present but classified as NO KNOWN THREAT FOUND.'
    );
  }

  const hasRisk = riskFactors.length > 0;
  const severity: 'none' | 'low' | 'medium' | 'high' = !hasRisk
    ? 'none'
    : riskFactors.some((r) => r.includes('OTP') || r.includes('scam signals'))
    ? 'high'
    : riskFactors.length > 1
    ? 'medium'
    : 'low';

  return {
    hasRiskOfFalseNegative: hasRisk,
    riskSeverity: severity,
    detectedRiskFactors: riskFactors,
    investigatorNotice: hasRisk
      ? `[POTENTIAL FALSE-NEGATIVE ALERT] ${riskFactors.length} anomalous risk factor(s) detected during trace analysis.`
      : undefined,
  };
}

/**
 * Stores a diagnostic trace in the circular memory buffer and outputs a structured log.
 */
export function recordDiagnosticTrace(trace: DiagnosticTrace): void {
  traceBuffer.unshift(trace);
  if (traceBuffer.length > MAX_TRACES) {
    traceBuffer.pop();
  }

  logDiagnosticTrace(trace);
}

/**
 * Formats a single diagnostic trace into a human-readable console and debug log.
 */
export function formatDiagnosticSummary(trace: DiagnosticTrace): string {
  const ocr = trace.ocrStage;
  const claims = trace.claimsStage;
  const path = trace.decisionPath;
  const risk = trace.falseNegativeAudit;

  const lines: string[] = [
    `==================== [DIAGNOSTIC TRACE ${trace.traceId}] ====================`,
    `Timestamp: ${trace.timestamp} | Duration: ${trace.executionDurationMs}ms | Source: ${trace.source}`,
    `--- STAGE 1: OCR EXTRACTION ---`,
    `Readable: ${ocr.isReadable} | Length: ${ocr.rawTextLength} chars | Model: ${ocr.ocrModelUsed}`,
    `Sender: "${ocr.sender}" (Classification: ${ocr.senderClassification})`,
    `Document Type: ${ocr.documentType}`,
    `Decoded Text Sample: "${ocr.rawText.slice(0, 120)}${ocr.rawText.length > 120 ? '...' : ''}"`,
    ocr.qrCodeDecoded ? `Decoded QR Payload: ${ocr.qrCodeDecoded}` : `Decoded QR Payload: None`,
    `--- STAGE 2: EXTRACTED CLAIM IDENTIFIERS ---`,
    `Candidate URLs: [${claims.urls.join(', ')}]`,
    `Reference Numbers: [${claims.referenceNumbers.join(', ')}]`,
    `Financial Amounts: [${claims.amounts.join(', ')}]`,
    `Claimed Entities: [${claims.claimedEntities.join(', ')}]`,
    `Document Flags: Challan=${claims.isChallanOrFine}, Receipt=${claims.isBankOrTransferReceipt}, Advisory=${claims.isProtectiveAdvisory}`,
    `Scam Signals Detected (${claims.scamSignalsDetected.length}): [${claims.scamSignalsDetected.join(' | ')}]`,
    `--- STAGE 3: CLASSIFICATION POLICY DECISION PATH ---`,
    `Evaluated Rule: ${path.evaluatedRule} (${path.ruleClause})`,
    `Rationale: ${path.ruleRationale}`,
    `Truth Table Flags:`,
    `  hasConfirmedThreatIntel: ${path.conditionTruthTable.hasConfirmedThreatIntel}`,
    `  hasBrandImpersonation: ${path.conditionTruthTable.hasBrandImpersonation}`,
    `  hasActiveFraudSignals: ${path.conditionTruthTable.hasActiveFraudSignals}`,
    `  demandsOtp: ${path.conditionTruthTable.demandsOtp} (isNegated: ${path.conditionTruthTable.isNegatedOtp})`,
    `  demandsAdvanceFeeOrLottery: ${path.conditionTruthTable.demandsAdvanceFeeOrLottery}`,
    `  extortionThreat: ${path.conditionTruthTable.extortionThreat}`,
    `  isPrivateSimSender: ${path.conditionTruthTable.isPrivateSimSender}`,
    `  isSuspiciousUrl: ${path.conditionTruthTable.isSuspiciousUrl}`,
    `  hasSecurityBlock: ${path.conditionTruthTable.hasSecurityBlock}`,
    `Verdict: ${path.verdict} | Category: ${path.verdictCategory} | Badge: ${path.badgeColor}`,
    `Status Label: ${path.statusLabel}`,
  ];

  if (risk.hasRiskOfFalseNegative) {
    lines.push(`--- STAGE 4: FALSE-NEGATIVE RISK AUDIT ---`);
    lines.push(`WARNING: POTENTIAL FALSE NEGATIVE (Severity: ${risk.riskSeverity.toUpperCase()})`);
    for (const factor of risk.detectedRiskFactors) {
      lines.push(`  ! ${factor}`);
    }
  } else {
    lines.push(`--- STAGE 4: FALSE-NEGATIVE RISK AUDIT: Clean (No incongruence detected) ---`);
  }

  lines.push(`========================================================================`);
  return lines.join('\n');
}

/**
 * Emits the formatted diagnostic trace to console.log for runtime inspection.
 */
export function logDiagnosticTrace(trace: DiagnosticTrace): void {
  console.log(formatDiagnosticSummary(trace));
}

/**
 * Retrieves the most recent diagnostic logs.
 */
export function getRecentDiagnosticLogs(limit = 20): DiagnosticTrace[] {
  return traceBuffer.slice(0, Math.min(limit, traceBuffer.length));
}

/**
 * Finds a specific diagnostic trace by its ID.
 */
export function getDiagnosticLogById(traceId: string): DiagnosticTrace | null {
  return traceBuffer.find((t) => t.traceId === traceId) || null;
}

/**
 * Returns any traces flagged for potential false-negative classification.
 */
export function getFalseNegativeCandidates(): DiagnosticTrace[] {
  return traceBuffer.filter((t) => t.falseNegativeAudit.hasRiskOfFalseNegative);
}

/**
 * Clears the diagnostic buffer (useful for test runs).
 */
export function clearDiagnosticLogs(): void {
  traceBuffer.length = 0;
}
