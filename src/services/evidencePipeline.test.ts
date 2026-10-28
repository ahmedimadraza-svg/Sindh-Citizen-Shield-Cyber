import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateEvidence,
  type StandardVerdict,
} from './classificationPolicy.ts';
import {
  investigateScreenshotEvidence,
  investigateLink,
  querySafeBrowsing,
} from './sharedEvidencePipeline.ts';
import {
  validateAndSanitizeUrl,
  isPrivateOrReservedIp,
  detectBrandImpersonation,
  matchAuthoritativeRegistry,
} from './investigationService.ts';
import { decodeQrFromImageBuffer } from './qrService.ts';

// =========================================================================
// TASK 9: 16 COMPREHENSIVE REPEATABLE AUDIT TESTS
// =========================================================================

// 1. Genuine public FIA warning against scams
test('1. Genuine public FIA warning against scams', async () => {
  const fiaText =
    'PUBLIC ADVISORY - FIA CYBER CRIME WING: Never share your OTP, PIN, or bank passwords with callers claiming to be officials. Report fraud to Helpline 1991 or complaint.fia.gov.pk.';
  const report = await investigateScreenshotEvidence({
    rawText: fiaText,
    sender: '1991',
  });

  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
  assert.equal(report.emergencyHelplineNeeded, false);
  assert.ok(report.evidence.some((e) => e.includes('public safety advisory')));
  assert.equal(report.fiveQuestions.questionB_suspiciousInstructions.summary.includes('No payment demands'), true);
});

// 2. An FIA-looking message demanding payment through an unrelated URL
test('2. FIA-looking message demanding payment through an unrelated URL', async () => {
  const fakeFiaText =
    'FIA Cyber Notice: Legal action initiated against your CNIC. Pay penalty fee immediately to avoid arrest: http://fia-fine-clearance.xyz/pay';
  const report = await investigateScreenshotEvidence({
    rawText: fakeFiaText,
    sender: '+92 312 9988776',
  });

  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.ok(report.fiveQuestions.questionC_destinationUrl.findings?.includes('fia'));
  assert.equal(report.emergencyHelplineNeeded, true);
});

// 3. Genuine Zong or Ufone notification with no suspicious instructions
test('3. Genuine Zong or Ufone notification with no suspicious instructions', async () => {
  const zongText =
    'Dear Customer, your Weekly Super Load bundle has been successfully subscribed. Remaining data: 12,000 MB valid till midnight. Dial *310# for details.';
  const report = await investigateScreenshotEvidence({
    rawText: zongText,
    sender: '310',
  });

  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
  assert.equal(report.emergencyHelplineNeeded, false);
  assert.ok(report.evidence.some((e) => e.includes('ZONG')));
});

// 4. An official-looking SMS with an unverified sender
test('4. Official-looking SMS with an unverified sender', async () => {
  const text = 'Important update regarding government civic database records. Visit portal for info: http://community-records-pak.org';
  const report = await investigateScreenshotEvidence({
    rawText: text,
    sender: '+92 345 1122334',
  });

  // Must NOT accuse innocent unfamiliar sender of confirmed threat without scam demands
  assert.notEqual(report.verdict, 'CONFIRMED THREAT');
  // Sender must be explicitly flagged as unverified
  assert.equal(report.fiveQuestions.questionE_senderAuthenticated.summary.includes('Unverified'), true);
});

// 5. Fake prize image requesting an advance fee
test('5. Fake prize image requesting an advance fee', async () => {
  const prizeText =
    'Mubarak Ho! You won 25,000 cash grant from BISP. Transfer processing fee of Rs. 1500 to claim or call 0345-8899112';
  const report = await investigateScreenshotEvidence({
    rawText: prizeText,
    sender: '+92 345 8899112',
  });

  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.ok(report.fiveQuestions.questionB_suspiciousInstructions.summary.includes('advance-fee'));
});

// 6. Fake bank message requesting an OTP
test('6. Fake bank message requesting an OTP', async () => {
  const bankOtpText =
    'Your mobile wallet is temporarily blocked. Please share OTP code 8821 with representative to unblock account.';
  const report = await investigateScreenshotEvidence({
    rawText: bankOtpText,
    sender: '+92 300 4455667',
  });

  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.ok(report.fiveQuestions.questionB_suspiciousInstructions.summary.includes('One-Time Password (OTP)'));
});

// 7. Screenshot with a look-alike official domain
test('7. Screenshot with a look-alike official domain', () => {
  const lookalike1 = detectBrandImpersonation('bisp.gov.pk.fake-portal.xyz', '/');
  assert.equal(lookalike1.impersonating, true);
  assert.equal(lookalike1.officialDomain, 'bisp.gov.pk');

  const lookalike2 = detectBrandImpersonation('fia-gov-pk.com', '/login');
  assert.equal(lookalike2.impersonating, true);
  assert.equal(lookalike2.officialDomain, 'fia.gov.pk');

  const lookalike3 = detectBrandImpersonation('zong-free-data-claim.xyz', '/');
  assert.equal(lookalike3.impersonating, true);
  assert.equal(lookalike3.officialDomain, 'zong.com.pk');
});

// 8. Image containing a QR code with a suspicious destination
test('8. Image containing a QR code with a suspicious destination', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Scan QR code to verify your beneficiary grant',
    sender: 'Unknown',
    qrCodeUrl: 'http://bisp-welfare-portal.xyz/claim-grant',
  });

  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.ok(report.fiveQuestions.questionC_destinationUrl.findings?.includes('bisp'));
});

// 9. Unreadable or cropped screenshot
test('9. Unreadable or cropped screenshot', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: '',
  });

  assert.equal(report.verdict, 'UNABLE TO VERIFY');
  assert.equal(report.badgeColor, 'slate');
  assert.ok(report.statusLabel.includes('UNREADABLE'));
});

// 10. Legitimate message that cannot be independently verified online
test('10. Legitimate message that cannot be independently verified online', async () => {
  // A routine message from a courier or shop
  const courierText = 'Your shipment PK-88291 has been dispatched via BlueEx. Expected delivery tomorrow.';
  const report = await investigateScreenshotEvidence({
    rawText: courierText,
    sender: 'BlueEx',
  });

  // Must NOT accuse legitimate private communication of fraud
  assert.notEqual(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  // Must clarify that private tracking database is not checked
  assert.ok(report.fiveQuestions.questionE_senderAuthenticated.findings?.includes('cannot'));
});

// 11. URL with a known threat match in a safe, established test fixture
test('11. URL with a known threat match in a safe, established test fixture', async () => {
  // Safe Browsing established test URL
  const testUrl = 'http://testsafebrowsing.appspot.com/s/phishing.html';
  const report = await investigateLink(testUrl);

  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.ok(report.evidence.some((e) => e.includes('threat match') || e.includes('SOCIAL_ENGINEERING')));
});

// 12. Empty threat-intelligence response
test('12. Empty threat-intelligence response', () => {
  const decision = evaluateEvidence({
    urlsExtracted: ['https://unfamiliar-harmless-blog.org'],
    threatIntelResult: {
      checked: true,
      hasThreatMatch: false,
      threatTypes: [],
    },
  });

  assert.equal(decision.verdict, 'NO KNOWN THREAT FOUND');
  // CRITICAL: Must include explicit disclaimer that empty threat intel is NOT proof of authenticity!
  assert.ok(
    decision.unverifiedClaims.some(
      (c) => c.includes('absence of a threat report') || c.includes('NEVER a guarantee')
    )
  );
});

// 13. Threat-intelligence timeout
test('13. Threat-intelligence timeout', () => {
  const decision = evaluateEvidence({
    urlsExtracted: ['https://example.com'],
    threatIntelResult: {
      checked: false,
      hasThreatMatch: false,
      error: 'Lookup timed out (5s limit)',
    },
  });

  // Timeout should not crash and must not falsely claim verified threat
  assert.notEqual(decision.verdict, 'CONFIRMED THREAT');
});

// 14. Redirect to a blocked private or internal address
test('14. Redirect to a blocked private or internal address', async () => {
  // SSRF defense validation on private IPv4 and loopback
  const loopback = await validateAndSanitizeUrl('http://127.0.0.1:8080/internal');
  assert.equal(loopback.valid, false);
  assert.ok(loopback.reason?.includes('private/reserved') || loopback.reason?.includes('blocked'));

  const metadata = isPrivateOrReservedIp('169.254.169.254');
  assert.equal(metadata, true);

  const local192 = isPrivateOrReservedIp('192.168.1.1');
  assert.equal(local192, true);

  const local10 = isPrivateOrReservedIp('10.0.0.1');
  assert.equal(local10, true);
});

// 15. Repeated analysis of the same unchanged image (10x stability test)
test('15. Repeated analysis of the same unchanged image (10 iterations)', async () => {
  const testSample = {
    rawText:
      'PUBLIC ADVISORY - FIA CYBER CRIME WING: Never share your OTP, PIN, or bank passwords with callers claiming to be officials. Report fraud to Helpline 1991 or complaint.fia.gov.pk.',
    sender: '1991',
    imageHash: 'fixed-fia-advisory-hash-audit-12345',
  };

  const results: StandardVerdict[] = [];

  for (let i = 0; i < 10; i++) {
    const report = await investigateScreenshotEvidence(testSample);
    results.push(report.verdict);
  }

  // All 10 iterations must produce the identical verdict!
  const firstVerdict = results[0];
  assert.equal(firstVerdict, 'NO KNOWN THREAT FOUND');
  for (let i = 1; i < results.length; i++) {
    assert.equal(
      results[i],
      firstVerdict,
      `Iteration ${i + 1} produced ${results[i]} instead of ${firstVerdict}`
    );
  }
});

// 16. Repeated checks of the same URL under unchanged evidence (10x stability test)
test('16. Repeated checks of the same URL under unchanged evidence (10 iterations)', async () => {
  const testUrl = 'https://bisp.gov.pk';
  const results: StandardVerdict[] = [];

  for (let i = 0; i < 10; i++) {
    const report = await investigateLink(testUrl);
    results.push(report.verdict);
  }

  // All 10 iterations must produce the exact same verdict!
  const firstVerdict = results[0];
  assert.equal(firstVerdict, 'NO KNOWN THREAT FOUND');
  for (let i = 1; i < results.length; i++) {
    assert.equal(
      results[i],
      firstVerdict,
      `Iteration ${i + 1} produced ${results[i]} instead of ${firstVerdict}`
    );
  }
});
