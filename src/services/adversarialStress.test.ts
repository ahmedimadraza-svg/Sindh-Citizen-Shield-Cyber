import test from 'node:test';
import assert from 'node:assert/strict';
import {
  investigateScreenshotEvidence,
  investigateLink,
  clearPipelineCache,
} from './sharedEvidencePipeline.ts';
import { validateAndSanitizeUrl } from './investigationService.ts';

// =========================================================================
// 42-CASE ADVERSARIAL ACCURACY STRESS TEST SUITE
// =========================================================================

// --- CATEGORY 1: Genuine public safety warnings (mentions OTP only to warn users) ---
test('ADV-01: Genuine FIA public safety advisory warning against OTP sharing', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'PUBLIC SAFETY ADVISORY - FIA CYBER CRIME: Never share your OTP, PIN or banking password with any caller claiming to be an official. Dial 1991 to report fraud.',
    sender: '1991',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
  assert.equal(report.emergencyHelplineNeeded, false);
  assert.equal(report.fiveQuestions.questionE_senderAuthenticated.summary.startsWith('Sender not independently verified'), true);
});

test('ADV-02: Genuine NCCIA advisory warning against phishing links', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'SECURITY ALERT - NCCIA: Beware of fraudulent text messages claiming prize money. Never disclose your mobile banking credentials or OTPs. Official portal: nccia.gov.pk',
    sender: 'NCCIA',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
});

test('ADV-03: Genuine State Bank of Pakistan warning against credential sharing', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'STATE BANK OF PAKISTAN ADVISORY: SBP or commercial banks never call customers to ask for ATM PINs, OTP codes, or passwords. Keep your banking data confidential.',
    sender: 'SBP',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('ADV-04: Genuine BISP public alert warning that 8171 is the only official shortcode', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'BISP PUBLIC NOTICE: BISP never contacts beneficiaries from private mobile numbers. Shortcode 8171 is the only official communication channel. Never give OTP or payment to anyone.',
    sender: '8171',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

// --- CATEGORY 2: Routine telecom notifications and legitimate SIM-count info ---
test('ADV-05: Routine PTA 668 SIM count notification', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Dear Citizen, Total active SIMs registered against CNIC 42101-*******-3 are: Jazz: 1, Telenor: 0, Zong: 0, Ufone: 0. Total: 1. Discrepancies visit cnic.sims.pk',
    sender: '668',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
  assert.equal(report.fiveQuestions.questionE_senderAuthenticated.summary.startsWith('Sender not independently verified'), true);
});

test('ADV-06: Routine Zong 310 weekly bundle subscription notification', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Dear Customer, your Weekly Super Load bundle has been successfully subscribed. Remaining data: 12,000 MB valid till midnight. Dial *310# for details.',
    sender: '310',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
});

test('ADV-07: Routine Ufone 333 Super Card recharge confirmation', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Muaziz Sarif, aapka Super Card Max kamyabi se load ho chuka hai. 30 din k liye 5000 MBs, 5000 U-U/PTCL mins aur 350 off-net mins muft faraham kiye gaye hain.',
    sender: '333',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('ADV-08: Routine Telenor 345 balance alert', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Dear Customer, your remaining balance is Rs. 142.50 valid till 30-Nov-2026. Dial *444# for customized recharge offers.',
    sender: '345',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

// --- CATEGORY 3: Genuine government notices with no links ---
test('ADV-09: Genuine Sindh Government public holiday notice with no links', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Government of Sindh, Services General Administration Department: It is hereby notified that Friday 23rd March shall be observed as a public holiday throughout the province.',
    sender: 'GovtSindh',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.notEqual(report.verdict, 'CONFIRMED THREAT');
  assert.notEqual(report.verdict, 'SUSPICIOUS');
});

test('ADV-10: Genuine Federal Education Board exam schedule notice with no links', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Federal Board of Intermediate and Secondary Education: Annual secondary school certificate examinations will commence from 15th April across designated test centers.',
    sender: 'FBISE',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('ADV-11: Genuine Provincial Disaster Management Authority flood advisory', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'PDMA Sindh Monsoon Alert: Heavy rainfall predicted in coastal districts during next 48 hours. Citizens are advised to avoid unnecessary travel and stay clear of electric poles.',
    sender: 'PDMASindh',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

// --- CATEGORY 4: Suspicious links with HTTP / unfamiliar TLDs but no proof of fraud ---
test('ADV-12: Unfamiliar community meeting announcement with unencrypted HTTP .xyz link', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Karachi Amateur Astronomers Society: Our monthly sky observation schedule is posted at http://karachi-astronomy-club.xyz/schedule. All members welcome.',
    sender: '+92 331 4455667',
    bypassCache: true,
  });
  // Must NOT accuse of confirmed threat without scam demands
  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.equal(report.badgeColor, 'amber');
});

test('ADV-13: Local sports tournament timetable on .top domain', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Check the cricket league match timings and ground allocations here: http://sindh-cricket-fixtures.top/matches',
    sender: '+92 312 9988771',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'SUSPICIOUS');
});

test('ADV-14: Student study group notes link on .click domain', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Physics past papers and solved notes uploaded: http://karachi-students-prep.click/notes',
    sender: '+92 345 6677889',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'SUSPICIOUS');
});

test('ADV-15: Private mobile SMS containing an unverified link with no scam requests', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Hey, photos from yesterday family gathering: http://family-photos-album.buzz/view',
    sender: '+92 333 1122445',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.notEqual(report.verdict, 'CONFIRMED THREAT');
});

// --- CATEGORY 5: Impersonation messages claiming official departments ---
test('ADV-16: Impersonation of BISP on lookalike domain', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'BISP 8171: Your welfare installment is pending. Confirm CNIC immediately: http://bisp-welfare-portal.xyz/claim',
    sender: '+92 345 8899112',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.ok(report.fiveQuestions.questionC_destinationUrl.findings?.includes('bisp'));
});

test('ADV-17: Impersonation of FIA on fake notice clearance domain', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'FIA Cyber Crime Notice: Legal summons issued. Download case file: http://fia-fine-clearance.xyz/summons',
    sender: '+92 301 2233445',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
});

test('ADV-18: Impersonation of PTA on fake SIM portal', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'PTA SIM Biometric Verification pending. Verify your identity to prevent blocking: http://pta-gov-pk.sims-pk.xyz/verify',
    sender: '+92 321 5566778',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

test('ADV-19: Impersonation of NADRA on fake CNIC renewal domain', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'NADRA Pak-Identity: Your CNIC verification expired. Renew online here: http://nadra-online-id.xyz/renew',
    sender: '+92 332 9988112',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

test('ADV-20: Impersonation of JazzCash on lookalike payment gateway', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'JazzCash Security: Unusual login detected on your wallet. Secure your account now: http://jazzcash-security-verify.xyz/login',
    sender: '+92 300 4455667',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

test('ADV-21: Impersonation of Easypaisa on unverified payment host', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Easypaisa reward! Claim Rs. 5000 cashback on your account: http://easypaisa-cashback-reward.xyz/claim',
    sender: '+92 341 8899001',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

// --- CATEGORY 6: Direct credential requests, OTP theft, fees, and extortion ---
test('ADV-22: Fake bank message requesting 6-digit OTP code', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Habib Bank Alert: We have restricted your debit card. To unlock your card, send your 6-digit OTP code to this number.',
    sender: '+92 334 5566778',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.emergencyHelplineNeeded, true);
});

test('ADV-23: Fake lottery prize requesting Rs. 2000 processing fee', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Congratulations! You won 50,000 cash grant in Pakistan National Draw. Call 0345-1234567 and send Rs. 2000 transfer fee to receive your prize.',
    sender: '+92 345 1234567',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.emergencyHelplineNeeded, true);
});

test('ADV-24: Coercive extortion threat demanding ransom payment', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'We have your private video and call recordings. Send ransom of Rs. 100,000 immediately or we broadcast to all contacts on your phone.',
    sender: '+92 311 9988776',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.emergencyHelplineNeeded, true);
});

test('ADV-25: Fake police arrest warrant demanding penalty fee', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Legal action initiated against your CNIC. Non-bailable arrest warrant issued. Pay penalty fee immediately to avoid arrest: http://clearance-pay.xyz/fine',
    sender: '+92 301 7788990',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.emergencyHelplineNeeded, true);
});

test('ADV-26: Phishing SMS from private 11-digit mobile SIM claiming BISP wazeefa', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Benazir Income Support 25000 grant approved. Send 4-digit JazzCash OTP immediately to claim or call 0345-9988776.',
    sender: '+92 345 9988776',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

test('ADV-27: Mobile wallet PIN solicitation via SMS', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Your mobile wallet account has suspicious activity. Enter your 4-digit MPIN to verify account ownership.',
    sender: '+92 331 2233445',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

// --- CATEGORY 7: Displayed branding that cannot be independently authenticated ---
test('ADV-28: Routine bank maintenance alert from HBL (no links, no credential requests)', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'HBL Info: Our digital banking services will undergo routine system maintenance on Sunday 02:00 AM to 05:00 AM. Inconvenience regretted.',
    sender: 'HBL',
    bypassCache: true,
  });
  // Must NOT accuse routine informational notification of being fraud
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.fiveQuestions.questionE_senderAuthenticated.summary.startsWith('Sender not independently verified'), true);
});

test('ADV-29: Routine courier delivery alert with tracking code (no links, no payment requests)', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'TCS Express: Your shipment with tracking number 7788990011 is out for delivery today. Delivery agent will arrive by 5 PM.',
    sender: 'TCS',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.fiveQuestions.questionE_senderAuthenticated.summary.startsWith('Sender not independently verified'), true);
});

// --- CATEGORY 8: Cropped, unreadable, or empty screenshots ---
test('ADV-30: Completely blank image submission', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: '',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'UNABLE TO VERIFY');
  assert.equal(report.badgeColor, 'slate');
});

test('ADV-31: Unreadable whitespace-only screenshot', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: '     \n\t   ',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'UNABLE TO VERIFY');
  assert.equal(report.badgeColor, 'slate');
});

// --- CATEGORY 9: QR codes to legitimate, suspicious, or blocked destinations ---
test('ADV-32: QR code pointing to official FIA complaint portal', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Scan to register cyber crime complaint with FIA',
    sender: 'FIA',
    qrCodeUrl: 'https://complaint.fia.gov.pk',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
});

test('ADV-33: QR code pointing to suspicious unverified .buzz domain', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Scan QR code for flyer info',
    sender: 'Unknown',
    qrCodeUrl: 'http://flyer-promo-host.buzz/info',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.equal(report.badgeColor, 'amber');
});

test('ADV-34: QR code pointing to blocked loopback IP (127.0.0.1)', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Scan QR to configure router',
    qrCodeUrl: 'http://127.0.0.1:8080/admin',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'UNABLE TO VERIFY');
  assert.equal(report.badgeColor, 'slate');
  assert.ok(report.evidence.some((e) => e.includes('SSRF') || e.includes('private')));
});

test('ADV-35: QR code pointing to blocked cloud metadata IP (169.254.169.254)', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Scan QR to test connection',
    qrCodeUrl: 'http://169.254.169.254/latest/meta-data/',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'UNABLE TO VERIFY');
  assert.equal(report.badgeColor, 'slate');
});

test('ADV-36: QR code pointing to deceptive BISP welfare fraud URL', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Scan QR code to receive your approved beneficiary cash grant',
    qrCodeUrl: 'http://bisp-welfare-portal.xyz/claim-grant',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
});

// --- CATEGORY 10: Threat-intelligence states & SSRF link inspections ---
test('ADV-37: Known Google Safe Browsing threat match URL fixture', async () => {
  const report = await investigateLink('http://testsafebrowsing.appspot.com/s/phishing.html', {
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
  assert.equal(report.badgeColor, 'red');
  assert.equal(report.emergencyHelplineNeeded, false); // Link check without active OTP request
});

test('ADV-38: Safe Browsing clean record on established public domain (Wikipedia)', async () => {
  const report = await investigateLink('https://en.wikipedia.org/wiki/Cybercrime', {
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
  assert.ok(report.unverifiedClaims.some((c) => c.includes('NEVER a guarantee')));
});

test('ADV-39: SSRF Blocked private IP address in link investigation', async () => {
  const report = await investigateLink('http://192.168.1.1/admin', { bypassCache: true });
  assert.equal(report.verdict, 'UNABLE TO VERIFY');
  assert.equal(report.badgeColor, 'slate');
  assert.ok(report.evidence.some((e) => e.includes('SSRF') || e.includes('private')));
});

// --- NEAR-DUPLICATE ADVERSARIAL PAIRS (Single critical detail changed) ---
test('ADV-40A: Near-Duplicate 1A — Genuine warning: Never share your OTP', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Security Alert: Fraudsters are calling asking for OTPs. Never share your OTP with anyone. Stay safe.',
    sender: '1991',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('ADV-40B: Near-Duplicate 1B — Scam demand: Send us your OTP immediately', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Security Alert: Urgent account issue detected. Send us your OTP immediately to verify your identity.',
    sender: '+92 345 8899112',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

test('ADV-41A: Near-Duplicate 2A — PTA 668: Total SIM count disclosure', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'PTA 668: Total active SIMs registered against your CNIC is 2. Check details at cnic.sims.pk.',
    sender: '668',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('ADV-41B: Near-Duplicate 2B — PTA Impersonation extortion: Blocked SIM, pay penalty', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'PTA Notice: Your SIM is involved in illegal activity. Pay penalty fee immediately to avoid arrest: http://clearance-sim.xyz',
    sender: '+92 321 4455667',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

test('ADV-42A: Near-Duplicate 3A — Routine Zong package renewal notification', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Dear Customer, your Super Weekly Max has been renewed. 30 GB valid for 7 days. Dial *310# for details.',
    sender: '310',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('ADV-42B: Near-Duplicate 3B — Fraudulent Zong lottery prize demanding processing fee', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Mubarak! You won 50,000 cash grant from Zong. Call 0345-9988771 and pay processing fee Rs. 1500 to claim your prize.',
    sender: '+92 345 9988771',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'CONFIRMED THREAT');
});

// =========================================================================
// REGRESSION SUITE: GCASH / DSWD AYUDA CASH-ASSISTANCE SCREENSHOT
// =========================================================================
test('REGRESSION: GCash / DSWD Ayuda cash-assistance SMS screenshot is classified as SUSPICIOUS (amber badge)', async () => {
  const exactMessage =
    'You received P4700.00 from DSWD Ayuda via GCash. Please check your balance or update via https://bit.ly/gcash-0ne';

  const report = await investigateScreenshotEvidence({
    rawText: exactMessage,
    sender: 'GCash',
    bypassCache: true,
  });

  // 1. Strict Verdict & Badge Color assertion
  assert.equal(report.verdict, 'SUSPICIOUS', 'Must be classified as SUSPICIOUS');
  assert.equal(report.badgeColor, 'amber', 'Badge color must be amber');
  assert.equal(report.statusLabel, 'SUSPICIOUS — INVESTIGATION NEEDED');

  // 2. Evidence must explain unexpected assistance claim
  assert.ok(
    report.evidence.some(
      (e) =>
        e.toLowerCase().includes('ayuda') ||
        e.toLowerCase().includes('cash assistance') ||
        e.toLowerCase().includes('grant')
    ),
    'Evidence must explain unexpected government cash assistance / Ayuda claim'
  );

  // 3. Evidence must explain shortened external link hiding destination
  assert.ok(
    report.evidence.some(
      (e) =>
        e.toLowerCase().includes('shortened url') ||
        e.toLowerCase().includes('masks') ||
        e.toLowerCase().includes('shortener')
    ),
    'Evidence must explain shortened external link hiding destination'
  );

  // 4. Evidence must explain unverified destination
  assert.ok(
    report.evidence.some(
      (e) =>
        e.toLowerCase().includes('destination not verified') ||
        e.toLowerCase().includes('not been independently established')
    ),
    'Evidence must explain destination not verified'
  );

  // 5. Evidence must explain GCash external link restriction or account update demand
  assert.ok(
    report.evidence.some(
      (e) =>
        e.toLowerCase().includes('gcash') ||
        e.toLowerCase().includes('clickable link') ||
        e.toLowerCase().includes('balance check') ||
        e.toLowerCase().includes('update')
    ),
    'Evidence must cite GCash link policy violation or account update demand'
  );

  // 6. Sender authentication: Carrier transmission cannot be proven from screenshot
  assert.ok(
    report.fiveQuestions.questionE_senderAuthenticated.findings?.toLowerCase().includes('sender not independently verified'),
    'Sender authenticity must record Sender not independently verified'
  );

  // 7. Unverified claims must clarify empty threat intelligence is not proof of safety
  assert.ok(
    report.unverifiedClaims.some((u) => u.includes('NEVER proof') || u.includes('not been independently established')),
    'Must explicitly state that empty threat intelligence does not prove safety'
  );
});

test('NEGATIVE CONTROL 1: Genuine public safety warning from GCash against sharing credentials', async () => {
  const advisoryMessage =
    'GCash Advisory: Never share your MPIN or OTP with anyone. GCash will never send SMS with clickable links to update your account. Report scams to 2882.';

  const report = await investigateScreenshotEvidence({
    rawText: advisoryMessage,
    sender: 'GCASH',
    bypassCache: true,
  });

  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.equal(report.badgeColor, 'emerald');
});

test('NEGATIVE CONTROL 2: Legitimate transaction notification receipt without suspicious links', async () => {
  const transactionMessage =
    'You have received P4,700.00 from Juan Dela Cruz. Your new GCash balance is P5,200.00. Ref. No. 1002348921.';

  const report = await investigateScreenshotEvidence({
    rawText: transactionMessage,
    sender: 'GCASH',
    bypassCache: true,
  });

  // Legitimate receipt without links or credential solicitation
  assert.equal(report.verdict, 'NO KNOWN THREAT FOUND');
  // Badge is neutral slate (receipt unverified against banking ledger) or emerald
  assert.ok(report.badgeColor === 'slate' || report.badgeColor === 'emerald');
});

test('REGRESSION: Scam link with high-risk TLD (free-recharge.buzz/claim) evaluated in investigateLink produces CONFIRMED THREAT or SUSPICIOUS', async () => {
  const report = await investigateLink('http://free-recharge.buzz/claim', { bypassCache: true });
  assert.ok(
    report.verdict === 'CONFIRMED THREAT' || report.verdict === 'SUSPICIOUS',
    `Expected CONFIRMED THREAT or SUSPICIOUS for scam URL with high-risk TLD, got ${report.verdict}`
  );
  assert.notEqual(report.verdict, 'NO KNOWN THREAT FOUND');
  assert.notEqual(report.statusLabel, 'UNABLE TO VERIFY (SECURITY RESTRICTED)');
});

test('REGRESSION: Shortener URL (https://bit.ly/gcash-0ne) in investigateLink evaluates to SUSPICIOUS', async () => {
  const report = await investigateLink('https://bit.ly/gcash-0ne', { bypassCache: true });
  assert.ok(
    report.verdict === 'SUSPICIOUS' || report.verdict === 'CONFIRMED THREAT',
    `Expected SUSPICIOUS or CONFIRMED THREAT for shortlink, got ${report.verdict}`
  );
  assert.notEqual(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('REGRESSION: Screenshot containing naked scam link (free-recharge.buzz/claim) extracts link and flags as CONFIRMED THREAT or SUSPICIOUS', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Congratulations! You won Rs 5000 free recharge. Click free-recharge.buzz/claim to get your recharge right now!',
    sender: '+92 345 9988776',
    bypassCache: true,
  });
  assert.ok(
    report.verdict === 'CONFIRMED THREAT' || report.verdict === 'SUSPICIOUS',
    `Expected CONFIRMED THREAT or SUSPICIOUS, got ${report.verdict}`
  );
  assert.notEqual(report.verdict, 'NO KNOWN THREAT FOUND');
});

test('REGRESSION: Screenshot containing naked shortener without scheme extracts link and flags as SUSPICIOUS', async () => {
  const report = await investigateScreenshotEvidence({
    rawText: 'Important notice regarding your mobile wallet balance. Check status here: bit.ly/gcash-0ne',
    sender: 'GCash',
    bypassCache: true,
  });
  assert.equal(report.verdict, 'SUSPICIOUS');
  assert.equal(report.badgeColor, 'amber');
});
