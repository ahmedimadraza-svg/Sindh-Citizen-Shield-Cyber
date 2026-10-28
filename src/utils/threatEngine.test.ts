import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, analyzeScreenshotText } from './threatEngine.ts';
import {
  validateAndSanitizeUrl,
  isPrivateOrReservedIp,
  detectBrandImpersonation,
  matchAuthoritativeRegistry,
} from '../services/investigationService.ts';

// 1. Phishing & Threat Identification
test('detects high-risk phishing URL matching brand impersonation decoy', () => {
  const result = analyzeUrl('http://bisp-welfare-cash.claim-now.xyz');
  assert.equal(result.riskLevel, 'MALICIOUS');
  assert.equal(result.isOfficialGov, false);
  assert.ok(result.threatIndicators.some((i) => i.includes('Suspicious top-level domain')));
  assert.ok(result.threatIndicators.some((i) => i.includes('Misleading brand name')));
  assert.ok(result.recommendedAction.includes('Do NOT Click or Enter PIN'));
});

// 2. Official Government Allowlist Corroboration
test('authenticates official government domains as safe', () => {
  const result = analyzeUrl('https://bisp.gov.pk/beneficiary');
  assert.equal(result.riskLevel, 'SAFE');
  assert.equal(result.isOfficialGov, true);
  assert.equal(result.threatScore, 0);
});

test('authenticates Sindh government portal as safe', () => {
  const result = analyzeUrl('https://sindh.gov.pk');
  assert.equal(result.riskLevel, 'SAFE');
  assert.equal(result.isOfficialGov, true);
});

// 3. False-Positive Reduction: Ordinary Unfamiliar Websites
test('does NOT falsely accuse ordinary unfamiliar websites of being malicious', () => {
  const result = analyzeUrl('https://example-community-blog.org');
  // Must NOT be labeled MALICIOUS merely because it is not government
  assert.notEqual(result.riskLevel, 'MALICIOUS');
  assert.equal(result.isOfficialGov, false);
});

// 4. Fraudulent SMS & Blackmail Detection
test('identifies high-risk SMS screenshot text with private SIM and welfare scam', () => {
  const text = 'Congratulations! You won 25,000 cash grant. Share OTP to claim or call 0345-XXXXXXX';
  const result = analyzeScreenshotText(text, { sender: '+92 345 8892102' });
  assert.equal(result.riskAssessment, 'HIGH RISK FRAUD ATTEMPT');
  assert.equal(result.riskBadge, 'HIGH RISK');
  assert.ok(result.detectedThreatIndicators.some((i) => i.includes('25,000 cash grant')));
  assert.ok(result.detectedThreatIndicators.some((i) => i.includes('private 11-digit SIM')));
  assert.ok(result.detectedThreatIndicators.some((i) => i.includes('solicitation of one-time password (OTP)')));
  assert.equal(result.emergencyContactNeeded, true);
});

test('identifies blackmail extortion threat signatures', () => {
  const text = 'Send ransom to this Easypaisa number or private recording will be broadcasted';
  const result = analyzeScreenshotText(text, { sender: '+92 312 9991122' });
  assert.equal(result.riskAssessment, 'HIGH RISK FRAUD ATTEMPT');
  assert.ok(result.detectedThreatIndicators.some((i) => i.includes('extortion') || i.includes('blackmail')));
});

// 5. False-Positive Reduction: Genuine PTA SIM Count Screenshot
test('does NOT falsely classify legitimate SIM count notification as a scam', () => {
  // A routine message from PTA shortcode 668 indicating 1 active SIM against CNIC
  const legitimateSimText = 'Dear Citizen, Total Active SIMs registered against CNIC 42201-1234567-1 are: Jazz: 1, Telenor: 0, Zong: 0, Ufone: 0. Total: 1.';
  const result = analyzeScreenshotText(legitimateSimText, { sender: '668' });

  // Must NOT accuse the citizen or PTA of a high-risk scam!
  assert.notEqual(result.riskAssessment, 'HIGH RISK FRAUD ATTEMPT');
  assert.equal(result.emergencyContactNeeded, false);
  assert.equal(result.riskBadge, 'LOW RISK');
});

// 6. SSRF & Private Network Security Gateway Tests
test('blocks loopback IP addresses (127.0.0.1, localhost)', async () => {
  const res = await validateAndSanitizeUrl('http://127.0.0.1:8080/admin');
  assert.equal(res.valid, false);
  assert.ok(res.reason?.includes('blocked') || res.reason?.includes('private'));

  const resLocalhost = await validateAndSanitizeUrl('http://localhost:3000');
  assert.equal(resLocalhost.valid, false);
});

test('blocks cloud metadata IP endpoint (169.254.169.254)', () => {
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.1'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.5'), true);
  // Public IP must not be blocked
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
});

test('blocks unsafe non-HTTP URL schemes (file:, javascript:, ftp:)', async () => {
  const fileScheme = await validateAndSanitizeUrl('file:///etc/passwd');
  assert.equal(fileScheme.valid, false);
  assert.ok(fileScheme.reason?.includes('Unsafe scheme'));
});

// 7. Authoritative Registry & Impersonation Tests
test('matches authoritative Pakistani institutions correctly', () => {
  const ptaMatch = matchAuthoritativeRegistry('cnic.sims.pk');
  assert.ok(ptaMatch);
  assert.equal(ptaMatch?.id, 'pta');

  const bispMatch = matchAuthoritativeRegistry('bisp.gov.pk');
  assert.ok(bispMatch);
  assert.equal(bispMatch?.id, 'bisp');
});

test('detects brand impersonation when official welfare name is used on non-gov domain', () => {
  const imp = detectBrandImpersonation('bisp-relief-grant.xyz', '/claim');
  assert.equal(imp.impersonating, true);
  assert.equal(imp.claimedOrg, 'Benazir Income Support Programme (BISP / 8171)');
  assert.equal(imp.officialDomain, 'bisp.gov.pk');
});

// 8. Safe Page Retrieval & SSRF Protection
test('blocks page retrieval on loopback IP', async () => {
  const { safeRetrievePageInfo } = await import('../services/investigationService.ts');
  const res = await safeRetrievePageInfo('http://127.0.0.1:3000/api/check-link');
  assert.equal(res.retrieved, false);
  assert.ok(res.failureReason?.includes('blocked') || res.failureReason?.includes('private'));
});

test('safely retrieves public webpage title and headers', async () => {
  const { safeRetrievePageInfo } = await import('../services/investigationService.ts');
  const res = await safeRetrievePageInfo('https://example.com');
  assert.equal(res.retrieved, true);
  assert.equal(res.httpStatus, 200);
  assert.equal(res.title, 'Example Domain');
});

