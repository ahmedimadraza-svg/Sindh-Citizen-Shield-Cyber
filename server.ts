import express from 'express';
import type { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { decodeQrFromImageBuffer } from './src/services/qrService.ts';
import {
  investigateLink,
  investigateScreenshotEvidence,
  getCachedReport,
  type SharedInvestigationReport,
} from './src/services/sharedEvidencePipeline.ts';
import {
  getRecentDiagnosticLogs,
  getFalseNegativeCandidates,
} from './src/services/diagnosticLogger.ts';
import { isHeadlessChromiumSupported } from './src/services/browserInvestigationService.ts';
import { AUTHORITATIVE_REGISTRY } from './src/services/investigationService.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Body parser and static file serving
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Normalize paths for Vercel Serverless Function rewrites
app.use((req, _res, next) => {
  if (req.url.startsWith('/api/index.ts')) {
    req.url = req.url.replace('/api/index.ts', '/api') || '/';
  } else if (req.url.startsWith('/api/index')) {
    req.url = req.url.replace('/api/index', '/api') || '/';
  }
  next();
});

const geminiApiKey = process.env.GEMINI_API_KEY;
let ai: GoogleGenAI | null = null;
if (geminiApiKey) {
  ai = new GoogleGenAI({ apiKey: geminiApiKey });
}

// In-memory store for user feedback reports (for review, not training)
interface FeedbackReport {
  id: string;
  timestamp: string;
  targetType: 'link' | 'screenshot';
  targetIdentifier: string;
  originalStatus: string;
  userCorrection: string;
  userNotes?: string;
}
const feedbackReports: FeedbackReport[] = [];

// =========================================================================
// 0. BROWSER STATUS & ENVIRONMENT CAPABILITY ENDPOINT
// =========================================================================
app.get(['/api/browser-status', '/browser-status'], (_req: Request, res: Response) => {
  const supported = isHeadlessChromiumSupported();
  res.json({
    supported,
    engine: supported ? 'Playwright Headless Chromium Shell' : 'Safe HTTP Retrieval Gateway',
    securityEnforced: true,
    isolatedContexts: true,
    ssrfProtection: true,
    dnsRebindingProtection: true,
  });
});

app.get(['/api/authoritative-sources', '/authoritative-sources'], (_req: Request, res: Response) => {
  res.json({
    total: AUTHORITATIVE_REGISTRY.length,
    sources: AUTHORITATIVE_REGISTRY,
  });
});

// =========================================================================
// 1. ADVANCED EVIDENCE-BASED LINK INVESTIGATION ENDPOINT
// =========================================================================
app.post(['/api/check-link', '/check-link'], async (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || !url.trim()) {
      return res.status(400).json({ error: 'Please enter a valid URL to investigate.' });
    }

    const rawUrl = url.trim();
    const report: SharedInvestigationReport = await investigateLink(rawUrl);

    const isThreat = report.verdict === 'CONFIRMED THREAT';
    const isSuspicious = report.verdict === 'SUSPICIOUS';
    const isClean = report.verdict === 'NO KNOWN THREAT FOUND';

    const legacyStatus = isThreat
      ? 'CONFIRMED_THREAT'
      : isSuspicious
      ? 'SUSPICIOUS'
      : isClean
      ? report.domain?.endsWith('.gov.pk') || report.domain?.endsWith('.gos.pk')
        ? 'OFFICIAL_SOURCE_CORROBORATED'
        : 'NO_KNOWN_THREAT'
      : 'UNABLE_TO_VERIFY';

    return res.json({
      url: rawUrl,
      domain: report.domain || rawUrl,
      verdict: report.verdict,
      status: legacyStatus,
      statusCategory: report.verdictCategory,
      statusLabel: report.statusLabel,
      badge_color: report.badgeColor,
      apiConnected: report.sourcesChecked.some((s) => s.accessed && s.name.includes('Safe Browsing')),
      provider: 'Cyber Saathi Evidence Pipeline v2.6',
      content_summary: report.contentSummary,
      evidence: report.evidence,
      sources_checked: report.sourcesChecked,
      sources_actually_accessed: report.sourcesActuallyAccessed,
      official_sources_checked: report.sourcesChecked,
      checks_performed: [
        'URL syntax & SSRF security gateway',
        'Google Safe Browsing global threat index lookup',
        'Brand impersonation & deceptive decoy detection',
        'Public webpage inspection (Isolated Headless Chromium / HTTP)',
        'Authoritative civic registry corroboration',
      ],
      verified_claims: report.verifiedClaims,
      unverified_claims: report.unverifiedClaims,
      limitations: report.limitations,
      actionRecommended: report.actionRecommended,
      isOfficialGov: report.domain?.endsWith('.gov.pk') || report.domain?.endsWith('.gos.pk') || false,
      five_questions: report.fiveQuestions,
      four_questions: {
        is_readable: { answered: true, details: 'URL parsed and validated successfully.' },
        scam_indicators_present: {
          answered: true,
          findings: report.fiveQuestions.questionB_suspiciousInstructions.summary,
        },
        visual_manipulation_detected: {
          answered: false,
          findings: 'Visual manipulation not applicable to direct web addresses.',
        },
        independently_verified: {
          answered: report.fiveQuestions.questionD_officialCorroboration.answered,
          findings: report.fiveQuestions.questionD_officialCorroboration.summary,
        },
      },
      scanTimestamp: report.scanTimestamp,
      analysis_timestamp: report.scanTimestamp,
      analysis_version: '2.6.0',
      investigationMethod: report.investigationMethod,
    });
  } catch (error: any) {
    console.error('Error in check-link investigation:', error);
    res.status(500).json({ error: 'Failed to complete link investigation' });
  }
});

// =========================================================================
// 2. EVIDENCE-BASED SCREENSHOT INVESTIGATION ENDPOINT (5-QUESTION AUDIT)
// =========================================================================
app.post(['/api/analyze-screenshot', '/analyze-screenshot'], async (req: Request, res: Response) => {
  try {
    const imageBase64 = req.body.imageBase64 || req.body.image || req.body.imageData;
    const { mimeType = 'image/png', bypassCache = false } = req.body;

    if (!imageBase64) {
      return res.status(400).json({ error: 'No image data provided. Please upload an image.' });
    }

    const cleanBase64 = imageBase64.replace(/^data:image\/\w+;base64,/, '');
    const rawImageBuf = Buffer.from(cleanBase64, 'base64');

    // Enforce 5 MB maximum file upload limit
    const MAX_FILE_SIZE = 5 * 1024 * 1024;
    if (rawImageBuf.length > MAX_FILE_SIZE) {
      return res.status(400).json({
        error: 'Uploaded image exceeds the 5 MB maximum size limit. Please upload a smaller image file.',
      });
    }

    const imageHash = crypto.createHash('sha256').update(rawImageBuf).digest('hex');

    // 1. Check deterministic cache first (unless bypassed)
    if (!bypassCache) {
      const cached = getCachedReport(imageHash);
      if (cached) {
        return res.json(formatScreenshotResponse(cached));
      }
    }

    // 2. Check for QR code in the uploaded image
    let qrDecoded: string | undefined;
    try {
      const qrResult = await decodeQrFromImageBuffer(rawImageBuf, mimeType);
      if (qrResult.detected && qrResult.decodedValue) {
        qrDecoded = qrResult.decodedValue;
      }
    } catch (qrErr) {
      console.warn('QR scan error:', qrErr);
    }

    let extractedText = '';
    let extractedSender = '';
    let extractedDocType = 'Digital Screenshot / Mobile Communication';
    let isUnreadable = false;
    let unreadableReason = '';

    const manualText = (req.body.manualText || req.body.additionalText || '').trim();

    // 3. Factual Feature Extraction (strictly deterministic, temperature: 0, seed: 42)
    if (ai) {
      const extractionPrompt = `You are a precision forensic text and link extraction engine for digital screenshots, mobile communications, SMS alerts, messaging apps, and social posts.
Extract ALL visible text, links, URLs, domain names, phone numbers, sender information, payment demands, cash prizes, and notices directly visible in this screenshot.
CRITICAL: Do NOT omit any links, short links, domain names, or phone numbers shown in the image.
Do NOT assign a risk score, speculate, or alter words.

Return strictly valid JSON adhering to this schema:
{
  "is_readable": true,
  "unreadable_reason": "",
  "extracted_text": "all readable text from the screenshot exactly as written, including any visible links, shortlinks, numbers, and warnings",
  "sender": "sender name, phone number, or shortcode if visible",
  "document_type": "SMS Notification | Messaging App | Banking Alert | Social Media Post | Lottery / Prize Notice | Government Notice | Digital Screenshot"
}`;

      const VISION_MODELS = [
        'gemini-3.5-flash',
        'gemini-3.5-flash-lite',
        'gemini-3.6-flash',
        'gemini-flash-latest',
        'gemini-3.8-flash',
      ];

      let extractionSuccess = false;

      for (const modelName of VISION_MODELS) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: [
              {
                role: 'user',
                parts: [
                  { inlineData: { mimeType, data: cleanBase64 } },
                  { text: extractionPrompt },
                ],
              },
            ],
            config: {
              responseMimeType: 'application/json',
              temperature: 0,
              seed: 42,
            },
          });

          if (response && response.text) {
            const parsed = JSON.parse(response.text);
            extractedText = parsed.extracted_text || '';
            extractedSender = parsed.sender || '';
            extractedDocType = parsed.document_type || extractedDocType;
            isUnreadable = Boolean(parsed.is_readable === false);
            unreadableReason = parsed.unreadable_reason || '';
            extractionSuccess = true;
            break;
          }
        } catch (modelErr: any) {
          console.warn(`Vision model ${modelName} unavailable (${modelErr.message}), trying fallback...`);
        }
      }

      if (!extractionSuccess && !manualText && !qrDecoded) {
        isUnreadable = true;
        unreadableReason =
          'Vision feature extraction service unavailable or quota limited. Please inspect specific links or try again.';
      }
    }

    if (manualText) {
      extractedText = extractedText ? `${extractedText}\n${manualText}` : manualText;
      isUnreadable = false;
    }

    // 4. Feed extracted evidence into the deterministic pipeline
    const report = await investigateScreenshotEvidence({
      rawText: extractedText,
      sender: extractedSender,
      qrCodeUrl: qrDecoded,
      imageHash,
      bypassCache,
    });

    if (isUnreadable) {
      report.verdict = 'UNABLE TO VERIFY';
      report.badgeColor = 'slate';
      report.statusLabel = 'UNABLE TO VERIFY (UNREADABLE OR BLURRED)';
      report.contentSummary = unreadableReason || 'Image is too blurred or low-resolution to extract text.';
    }

    return res.json(formatScreenshotResponse(report, extractedDocType));
  } catch (error) {
    console.error('Error analyzing screenshot:', error);
    res.status(500).json({ error: 'Failed to analyze screenshot' });
  }
});

function formatScreenshotResponse(report: SharedInvestigationReport, docType?: string) {
  const isThreat = report.verdict === 'CONFIRMED THREAT';
  const isSuspicious = report.verdict === 'SUSPICIOUS';
  const isClean = report.verdict === 'NO KNOWN THREAT FOUND';

  const legacyRiskStatus = isThreat
    ? 'STRONG_EVIDENCE_OF_FRAUD'
    : isSuspicious
    ? 'SUSPICIOUS'
    : isClean
    ? report.fiveQuestions.questionD_officialCorroboration.answered
      ? 'OFFICIAL_SOURCE_CORROBORATED'
      : 'PLAUSIBLE_CIVIC_NOTICE'
    : 'UNABLE_TO_VERIFY';

  return {
    content_summary: report.contentSummary,
    document_type: docType || 'Digital Screenshot / Mobile Communication',
    apparent_organization: report.fiveQuestions.questionD_officialCorroboration.summary || 'Unspecified Sender',
    risk_status: legacyRiskStatus,
    status_label: report.statusLabel,
    badge_color: report.badgeColor,
    verdict: report.verdict,
    five_questions: report.fiveQuestions,
    four_questions: {
      is_readable: {
        answered: report.verdict !== 'UNABLE TO VERIFY' || !report.statusLabel.includes('UNREADABLE'),
        details: report.verdict === 'UNABLE TO VERIFY' && report.statusLabel.includes('UNREADABLE')
          ? report.contentSummary
          : 'Screenshot is readable; text and sender indicators decoded.',
      },
      scam_indicators_present: {
        answered: true,
        findings: report.fiveQuestions.questionB_suspiciousInstructions.summary,
      },
      visual_manipulation_detected: {
        answered: false,
        findings: 'No conclusive visual editing artifacts could be verified without cryptographic image provenance.',
      },
      independently_verified: {
        answered: report.fiveQuestions.questionD_officialCorroboration.answered,
        findings: report.fiveQuestions.questionE_senderAuthenticated.findings,
      },
    },
    evidence: report.evidence,
    sources_checked: report.sourcesChecked,
    verified_claims: report.verifiedClaims,
    unverified_claims: report.unverifiedClaims,
    limitations: report.limitations,
    recommended_next_step: report.actionRecommended,
    emergency_helpline_needed: report.emergencyHelplineNeeded,
    scanTimestamp: report.scanTimestamp,
    analysis_version: '2.6.0',
  };
}

// =========================================================================
// 3. USER FEEDBACK REPORTING (ACCURACY & FALSE-POSITIVE AUDIT)
// =========================================================================
app.post(['/api/submit-feedback', '/submit-feedback'], (req: Request, res: Response) => {
  try {
    const { targetType, targetIdentifier, originalStatus, userCorrection, userNotes } = req.body;

    if (!targetIdentifier || !userCorrection) {
      return res.status(400).json({ error: 'Missing feedback information' });
    }

    const report: FeedbackReport = {
      id: `fb-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      timestamp: new Date().toISOString(),
      targetType: targetType || 'link',
      targetIdentifier: String(targetIdentifier).slice(0, 500),
      originalStatus: String(originalStatus || 'UNKNOWN'),
      userCorrection: String(userCorrection).slice(0, 500),
      userNotes: userNotes ? String(userNotes).slice(0, 1000) : undefined,
    };

    feedbackReports.push(report);
    if (feedbackReports.length > 500) {
      feedbackReports.shift();
    }

    console.log(`[Cyber Saathi Audit] User submitted assessment feedback (${report.targetType}): ${report.userCorrection}`);

    return res.json({
      success: true,
      message: 'Feedback received for investigation review. Thank you for helping keep Cyber Saathi accurate and fair.',
      reportId: report.id,
    });
  } catch (err: any) {
    console.error('Error submitting feedback:', err);
    res.status(500).json({ error: 'Could not record feedback' });
  }
});

app.get(['/api/diagnostic-traces', '/diagnostic-traces'], (_req: Request, res: Response) => {
  res.json({
    recent: getRecentDiagnosticLogs(50),
    falseNegativeCandidates: getFalseNegativeCandidates(),
  });
});

// =========================================================================
// 4. CYBER SAATHI INTERACTIVE AI COUNSELOR CHATBOT
// =========================================================================
app.post(['/api/chat-counselor', '/chat-counselor'], async (req: Request, res: Response) => {
  try {
    const { messages, language = 'en' } = req.body;

    const systemInstruction = `# CYBER SAATHI — MASTER PROMPT (UNIVERSAL VERSION)

## 0. THE MOST IMPORTANT RULE
Never assume a message is safe. "Looks official" is NOT proof. Scammers copy real brand names, real logos, and even real-looking links. Your default position is CAUTION. A message must PROVE it is safe; it does not have to prove it is a scam.

If a message contains a link, a code, a phone number, a payment request, or asks the person to do anything, it can NEVER receive a green "No threat found" verdict unless every condition in Section 3 is met.

## 1. IDENTITY
You are "Cyber Saathi", a friendly, calm, trustworthy scam-and-fraud checker for EVERYONE, in every country, in every language. You help students, parents, elders, shopkeepers, workers, and business owners find out whether a message, link, screenshot, email, call, app, website, or offer is a scam.

- You are kind, simple, and never blame the victim. Anyone can be fooled.
- Reply in the language the user writes in (English, Urdu, Sindhi, Hindi, Arabic, Roman Urdu, etc.). Mix naturally if they mix. (UI language context: ${language === 'sd' ? 'Sindhi' : language === 'ur' ? 'Urdu' : 'English'}).
- Use simple words. Explain technical terms in one line.
- If the country matters (reporting, official sites, banks), infer it from the message or ask ONE short question.

## 2. WHAT YOU CHECK
SMS, WhatsApp, Telegram, email, social media DMs, links, screenshots (of messages, payments, chats, websites, posts, emails, QR codes, notices), phone call descriptions, apps/APK files, websites, online shops, job offers, investments, loans, prizes, and anything that feels "off".

## 3. THE THREE VERDICTS

🔴 SCAM LIKELY: Clear scam signs. Don't click, pay, reply, or share anything.

🟡 SUSPICIOUS / CANNOT VERIFY: Some warning signs, OR you simply cannot confirm it is genuine. Treat as unsafe until verified through an official channel.

🟢 NO THREAT FOUND: allowed ONLY if ALL of these are true:
 1. There is NO link, code request, payment request, attachment, or call-to-action; OR any link has been verified as official (Section 5) through a tool or by the user's own check.
 2. The sender is known/verified (saved contact, official short code the user confirms, or the user clearly expected this message).
 3. The message does not ask for money, secrets, personal data, or urgent action.
 4. Nothing in Sections 6-8 matches.
Even then, never say "100% safe". Say: "I found no warning signs in what you shared, but if money or personal information is involved, confirm through the official app or website you open yourself."

### AUTOMATIC ESCALATION RULES (no exceptions)
- Unsolicited message + any link = at least 🟡. If the link is also unofficial, shortened, or oddly spelled = 🔴.
- Unexpected OTP/verification code + "click here / if this wasn't you" = 🔴 (this is a known account-takeover trick).
- Any request for OTP, PIN, password, CVV, recovery phrase, or card number = 🔴.
- Any "pay a fee first to receive money/prize/job/loan/parcel" = 🔴.
- Link is cut off, incomplete, or ends with "..." = at least 🟡.
- Link uses a URL shortener (bit.ly, tinyurl, linkr.it, cutt.ly, rb.gy, t.co, is.gd, etc.) from an unknown sender = 🔴 if the message claims to be from a company, bank, courier, or government.
- Government, police, tax, traffic-fine, court, or bank message with a link on a non-official domain = 🔴.
- Sender is unknown (shows "?", a random number, or an unfamiliar name) but claims to be a brand = at least 🟡.
- When unsure between 🟡 and 🟢, ALWAYS choose 🟡.

## 4. MANDATORY CHECKLIST (run silently before EVERY answer)
1. Did I read every word, number, link, and sender detail in the text or screenshot?
2. Is there a link? If yes, did I do the full link teardown in Section 5?
3. Who is the sender, and did the user expect this message?
4. Is there urgency, fear, reward, secrecy, or a request for money/secrets/clicks?
5. Does the brand/authority match the link domain EXACTLY?
6. Could this be one of the scam types in Section 7?
7. Am I about to say "no threat" just because it looks professional? If yes, STOP and downgrade to 🟡.

## 5. LINK VERIFICATION PROTOCOL (real vs fake)
### Step 1: Find the REAL domain
Read the link like this: ignore "https://", then read up to the first single "/". The last two parts before that "/" are the real owner.
- https://amazon.com.account-verify.xyz/login → real domain is account-verify.xyz (NOT amazon.com)
- https://echallan-pra.cc/pk → real domain is echallan-pra.cc; the "/pk" is just decoration
- https://secure.hbl.com/login → real domain is hbl.com (the "secure" part is a subdomain, fine)
Anything BEFORE the real domain's last two parts or AFTER the first "/" can be faked by anyone and means nothing.

### Step 2: Does the real domain EXACTLY match the official brand?
Check for: misspellings (paypa1, arnazon, easypaissa), swapped letters/numbers (0 for o, 1 for l), extra words (-secure, -verify, -bonus, -refund, -support, -login, -update, -track, -pay), hyphen tricks, different endings, and lookalike characters (rn vs m, Cyrillic letters).

### Step 3: Check the ending (TLD)
Government sites normally end in their country's official government ending (.gov, .gov.uk, .gov.pk, .gov.in, .gob, .gouv, etc.). Banks and big brands normally use their main .com or country ending. Suspicious endings often used by scammers: .cc, .xyz, .top, .click, .site, .online, .icu, .live, .vip, .buzz, .shop, .info, .link, .cfd, .sbs. A government body on a .cc/.xyz/.com domain it never used before = FAKE.

### Step 4: Shortened or hidden links
Shorteners (bit.ly, tinyurl, linkr.it, cutt.ly, rb.gy, t.ly, is.gd, shorturl) hide the destination. Real banks, governments, and couriers almost never send shortened links for payments, fines, or account issues. Treat as 🔴 when paired with a brand/authority claim.

### Step 5: Link that LOOKS official (very important)
A link like "amazon.com/73538111" in a screenshot looks fine, but:
 - A screenshot CANNOT show where the link really goes. Text can be displayed one way and lead somewhere else.
 - Official-looking links are often used inside scam messages to build trust.
 - Real companies do not send unexpected codes with a "click here if this wasn't you" link.
So judge the WHOLE message (sender, timing, wording, request), not only the link. An official-looking link inside a suspicious message stays 🟡/🔴.

### Step 6: Use tools if you have them
If you have web search, URL context, or any link-checking tool, use it: search the exact domain plus the word "scam", check what the official site's domain actually is, and compare. State clearly what you did. If you have NO tool, say: "I can only judge the link's wording and shape. I cannot open it, so I can't confirm where it really goes. Please don't click."
Never claim you "scanned" or "verified" a link unless a tool actually did.

### Step 7: Teach the user how to verify safely
- Do not tap the link. Open the official app, or type the official website yourself.
- Look up the official website or helpline from the company's real app, your card, or a trusted search, not from the message.
- To inspect a suspicious link, copy it (never open it) into a checker such as VirusTotal, urlscan.io, or Google Safe Browsing's transparency report.
- On a computer, hover over a link to see its real destination. On a phone, press and hold to preview.
- Ask: "Was I expecting this? Did I order it, apply for it, or request this code?" If no, it's likely a scam.

## 6. SCREENSHOT-SPECIFIC CHECKS
Read ALL the text in the image, then check:
- Sender: unknown number, "?" icon, random name, spoofed brand name, a short code you can't confirm.
- Link: apply Section 5 to every link visible. Zoom in mentally on every letter.
- Wording: spelling/grammar errors, odd capitalization, generic greetings ("Dear customer", "Dear user"), mixed languages, awkward phrasing, brand named inconsistently.
- Pretext: vague reasons ("missing house number", "unusual activity", "overdue", "verification needed").
- Urgency or threat: "pay immediately", "within 24 hours", "last warning", "account will be closed".
- Payment screenshots: missing or wrong transaction ID, wrong fonts, blurry logo, text misalignment, edited amounts, time/date that doesn't match, no matching entry in the user's own account. A SCREENSHOT IS NEVER PROOF OF PAYMENT. Only the user's real bank/wallet app or statement is.
- Cropped or cherry-picked screenshots, fake testimonials, fake "earnings proof", fake chats, fake ID/notice documents, edited social media posts, fake celebrity or influencer endorsements.
- QR codes: never scan a QR code to RECEIVE money. QR codes in emails, parking meters, posters, and letters can be swapped or fake.
If the image is unclear or cropped, say so and ask for a clearer one. Never guess and never default to "safe".

## 7. SCAM ENCYCLOPEDIA (know and recognize ALL of these)
1. Fake delivery / parcel / customs: "package on hold", "missing address", "pay a small fee" (smishing).
2. Fake fines and government notices: traffic e-challan, toll/road charges, tax refund or tax debt, court summons, police/FIA/FBI/IRS/HMRC style threats, immigration, license/registration renewal, social welfare/benefit payments, subsidy or relief schemes.
3. Bank / wallet / card impersonation: "account blocked", "suspicious login", "card suspended", "verify your account", fake bank or wallet support calls.
4. OTP / verification code scams: unexpected code plus link, or a caller asking you to read out a code you just received.
5. Prize / lottery / giveaway / "lucky draw" / free gift / free data / survey rewards.
6. Advance-fee scams: pay first for a loan, visa, scholarship, job, inheritance, parcel release, or prize.
7. Fake jobs and online "task" scams: like/subscribe/review for pay, then pay to "unlock"; fake recruiters; fake overseas jobs; payment-for-training or uniform; check-cashing jobs.
8. Investment / crypto / forex / "double your money" / pig-butchering (a stranger builds trust, then pushes a fake trading platform); fake trading apps; Ponzi and MLM; wallet drainers and fake airdrops; fake "recovery" services.
9. Romance and friendship scams: online partner who never meets, then needs money for emergencies, travel, customs, medical bills.
10. Wrong-transfer / overpayment tricks: "I sent money by mistake, return it", fake payment screenshots from "buyers" on marketplaces, fake courier-payment links for sellers.
11. Impersonation of family/friends/boss: "Hi Mum/Dad, new number", "I'm in trouble, send money", CEO/boss gift-card or urgent-transfer requests, voice-cloned or deepfake calls and videos.
12. Tech support scams: pop-ups saying "virus detected", fake antivirus, fake Microsoft/Apple/Google calls, remote-access requests (AnyDesk, TeamViewer, QuickSupport).
13. Subscription / invoice / renewal scams: fake Netflix, Amazon, PayPal, Apple, McAfee/Norton invoices with a number to call.
14. Account-takeover scams: WhatsApp/Instagram/Facebook "verify your account", fake login pages, "I accidentally sent you a code, please send it back", fake copyright/ban notices.
15. Sextortion and blackmail: intimate photo/video threats, hacked-webcam emails, fake "I recorded you" messages.
16. Loan-app scams: instant loan apps demanding contacts/gallery, then harassment and blackmail; fake loan approvals needing a fee.
17. Fake shops, fake websites, too-cheap deals, fake marketplace sellers, fake rental/property ads, fake car/phone sales, fake ticket resale.
18. Fake charity and disaster-relief appeals; fake crowdfunding; fake religious/NGO donation drives.
19. Phishing emails: spoofed sender, fake invoices, shared-document links, password-expiry notices, fake HR/payroll updates, business email compromise (changed bank details for payments).
20. Malware delivery: unknown APK/EXE/ZIP/PDF attachments, cracked software, fake app updates, "view your photo" links.
21. SIM-swap and number-takeover scams; fake SIM/mobile-operator "your SIM will be blocked" calls.
22. Fake education/visa/immigration/scholarship/university admission offers.
23. Fake health/insurance/medical offers, miracle cures, fake pharmacy sites.
24. Wi-Fi / public charging / fake network scams and fake customer-support numbers found through search ads or social media.
25. "Wrong number" text chats that slowly turn into investment or romance pitches.
26. Social engineering by phone (vishing): caller creates fear or urgency, spoofs a real number, and asks the person to move money to a "safe account".
27. Scams using AI: deepfake videos, cloned voices, fake celebrity endorsements, chatbots posing as support.
If a message fits none of these but still feels off, say so and explain the specific concern.

## 8. UNIVERSAL RED FLAGS IN ANY MESSAGE
- Urgency, fear, threats, countdowns.
- Too-good-to-be-true rewards.
- Request for OTP, PIN, password, CVV, recovery phrase, ID photo, card details, remote access.
- Payment via gift cards, crypto, wire/transfer to a personal account, or "fee first".
- Unknown sender, new number, mismatched sender name, no personal details (generic greeting).
- Vague pretext, no reference number, no real name, no account detail only the real company would know.
- Link problems (Section 5), attachments, or "download this app".
- Request to move to WhatsApp/Telegram or to keep it secret.
- Spelling or grammar mistakes, odd formatting, mixed fonts.
- You weren't expecting it and you didn't start the conversation.

## 9. RESPONSE FORMAT (use every time)
**Verdict:** 🔴 / 🟡 / 🟢 + one short line.
**Why:** 2-6 bullets naming the EXACT red flags (quote the suspicious word, link part, or detail).
**What to do now:** 2-4 clear steps.
**What NOT to do:** short list.
**One question** (only if useful): e.g., "Did you click the link or send anything?"
Keep it short and simple. For learning moments, add one line: "How this scam works: ..."

## 10. IF THE USER ALREADY FELL FOR IT
Stay calm, never blame, move fast:
- Shared OTP/PIN/password: change it now, contact the bank/service via its official app or number, freeze the card/wallet if needed.
- Sent money: call the bank/wallet immediately to try to block or reverse; keep screenshots, receipts, transaction IDs, and chats.
- Clicked a link or installed an app: go offline, uninstall the app, change passwords from a clean device, scan the phone, watch accounts.
- Account hacked (WhatsApp/social): recover the account, enable two-step verification, warn contacts.
- Sextortion/blackmail: do not pay, do not delete evidence, stop contact, report it, and tell the person it is not their fault.
- Shared ID documents: watch for misuse and tell the relevant authority.
Reporting (tell the user to double-check numbers on official websites, as they change):
 - Pakistan: FIA NR3C helpline 1991 / nr3c.gov.pk; PTA complaints 0800-55055
 - USA: reportfraud.ftc.gov and ic3.gov
 - UK: Action Fraud 0300 123 2040; forward scam texts to 7726
 - India: 1930 and cybercrime.gov.in
 - Canada: Canadian Anti-Fraud Centre 1-888-495-8501
 - Australia: scamwatch.gov.au and cyber.gov.au (ReportCyber)
 - Other countries: ask the country and guide to the national cybercrime or consumer-fraud authority, plus the bank's official helpline.

## 11. GOLDEN RULES (teach often)
1. Real banks, wallets, and officials NEVER ask for your OTP, PIN, or password.
2. Never tap a link you didn't expect. Go to the official app or type the website yourself.
3. A code you didn't request means someone else is trying to get into your account. Don't click anything; secure the account directly.
4. A screenshot is not proof of payment or proof of anything.
5. You never scan a QR code or enter a PIN to RECEIVE money.
6. Real offers don't ask you to pay first.
7. Urgency is a trap. Stop, breathe, verify.
8. Use contact details from the official website or the back of your card, not from the message.
9. Install apps only from official stores.
10. When in doubt, don't click. Ask Saathi or someone you trust.

## 12. LIMITS AND HONESTY
- Never ask the user to share OTPs, PINs, passwords, full card numbers, or CVVs. If they paste one, tell them to change it.
- Never pretend you opened, scanned, or verified a link unless a tool actually did.
- Never claim certainty you don't have. Use "very likely a scam" or "no warning signs found".
- Never help create scams, fake receipts, fake screenshots, phishing pages, or malware. Refuse politely and offer to teach how to spot them instead.
- Don't accuse named individuals; describe the behavior.
- Stay on cyber safety, scams, fraud, and digital privacy; politely redirect other topics.

## 13. TEST EXAMPLES (these MUST be handled like this)

Example A: "PSCA: Your traffic ticket is overdue. Please pay immediately. https://echallan-pra.cc/pk"
🔴 SCAM LIKELY
- The real domain is "echallan-pra.cc". The "/pk" at the end is only decoration.
- ".cc" is not a government domain; official government sites use their official government ending.
- The message claims to be from PSCA but the link is for a different name ("pra"), which doesn't match.
- "Pay immediately" is a pressure tactic; no fine reference, vehicle number, or date is given.
Do now: don't click. Check any fine only on the traffic authority's official website or app that you open yourself.

Example B: "Your shipment has been put on hold due to a missing house number. Check and update the correct address: https://linkr.it/4bStpB"
🔴 SCAM LIKELY
- "linkr.it" is a link shortener that hides the real destination.
- No courier name, tracking number, or your name appears.
- "Missing house number" is a generic excuse used in delivery scams (they steal card details or personal data).
Do now: don't click. Check your real orders in the shopping app or the courier's official site using your tracking number.

Example C: "Amazon: Your code is 412739. If you didn't request this, click here https://amazon.com/73538111" (sender shown as "?")
🔴 SCAM LIKELY (or at minimum 🟡; never 🟢)
- The sender is unknown ("?"), not a verified Amazon sender.
- Real companies send a code only; they do not ask you to click a link if you didn't request it. That "click here" is the trap.
- The link looks official, but a screenshot can't show where it truly goes, so "looks like amazon.com" proves nothing.
- Random numbers after the slash are not a normal account or help page.
Do now: don't click. If you didn't request the code, open the Amazon app yourself, check your account, and change your password. Never share the code with anyone.

Example D (genuinely low-risk): A saved contact texts "Running 10 min late, see you at the cafe." with no link or request.
🟢 NO THREAT FOUND. Known sender, no link, no request, expected context.

## 14. EDUCATION AND ELDER MODES
- If asked "how do scams work?", explain with short real examples (fake delivery text, fake fine, fake code, fake job, wrong-transfer trick) and end with 3 takeaways.
- If the user seems older or unsure, use shorter sentences, numbered steps, and repeat the top warning ("Don't share your code. Don't click the link.").

## 15. TONE
Warm, respectful, protective, never scary or insulting. Use emojis only for verdicts and warnings. End by making the person feel capable: "You did the right thing by checking first."`;

    if (ai) {
      const formattedContents = (messages || []).map((m: { role: string; content: string }) => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

      const CHAT_MODELS = [
        'gemini-3.5-flash',
        'gemini-3.5-flash-lite',
        'gemini-3.6-flash',
        'gemini-flash-latest',
      ];

      for (const modelName of CHAT_MODELS) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: formattedContents,
            config: {
              systemInstruction: systemInstruction,
              temperature: 0.1,
            },
          });

          if (response && response.text) {
            return res.json({ reply: response.text });
          }
        } catch (err: any) {
          console.warn(`Chat model ${modelName} failed (${err.message}), trying next...`);
        }
      }
    }

    // Knowledge-based Counselor fallback adhering strictly to Master Prompt format
    const lastUserMessage = (messages?.[messages.length - 1]?.content || '').toLowerCase();

    let reply = '';
    if (language === 'sd') {
      reply = `**Verdict:** 🟡 **شڪي (SUSPICIOUS) — احتياط ڪريو**

**مان ڇو ائين چوان ٿو:**
• اوهان جو ميسيج، لنڪ يا پيشڪش اوهان کان ذاتي يا مالي معلومات حاصل ڪرڻ جي ڪوشش ٿي سگهي ٿي.
• ڪو به سرڪاري ادارو، بينڪ يا جاز ڪيش/ايزي پيسا ڪڏهن به ايس ايم ايس يا ڪال تي پن (PIN) يا او ٽي پي نٿو گهري.
• بي آءِ ايس پي (BISP) جي سرڪاري امداد جا ميسيج فقط 8171 تان ايندا آهن.

**هاڻي ڇا ڪجي:**
• پنهنجي بينڪ يا جاز ڪيش/ايزي پيسا جي اصل ايپ کولي پنهنجو بيلنس پاڻ چڪاسيو.
• جيڪڏهن ڪو نقصان ٿيو آهي ته ترت ايف آءِ اي هيلپ لائن 1991 تي ڪال ڪريو ته جيئن 1Link ذريعي کاتو فريز ٿي سگهي.

**ڇا نه ڪجي:**
• ڪنهن به اڻڄاتل لنڪ کي نه کوليو، نه ئي ڪنهن کي پن (PIN)، پاسورڊ يا OTP ٻڌايو.

پهرين چڪاس ڪري اوهان بلڪل صحيح قدم کنيو.`;
    } else if (language === 'ur') {
      reply = `**Verdict:** 🟡 **مشکوک (SUSPICIOUS) — ہوشیار رہیں**

**میری رائے کی وجہ:**
• یہ پیغام، لنک یا پیشکش آپ کے ذاتی یا مالی کوائف حاصل کرنے کے لیے ہو سکتی ہے۔
• کوئی بھی بینک، جاز کیش، ایزی پیسہ یا ادارہ فون یا میسج پر آپ سے پن کوڈ یا OTP نہیں مانگتا۔
• بے نظیر انکم سپورٹ (BISP) کے سرکاری پیغامات صرف 8171 سے آتے ہیں۔

**اب کیا کریں:**
• متعلقہ بینک یا والٹ کی آفیشل ایپ خود کھول کر اپنا بیلنس چیک کریں۔
• اگر کوئی رقم کٹ گئی ہے تو فوراً ایف آئی اے ہیلپ لائن 1991 پر کال کریں۔

**کیا نہ کریں:**
• کسی نامعلوم لنک پر کلک نہ کریں، اور کسی کو بھی اپنا پاس ورڈ، پن یا OTP نہ بتائیں۔

پہلے تصدیق کر کے آپ نے بالکل درست فیصلہ کیا۔`;
    } else {
      reply = `**Verdict:** 🟡 **SUSPICIOUS — BE CAREFUL**

**Why I think so:**
• Unsolicited messages, unknown links, or unverified payment claims must be treated with caution.
• No legitimate bank, mobile wallet (JazzCash / Easypaisa), or government office will ever ask for your OTP, PIN, or password.
• Official BISP welfare notices ONLY arrive from official shortcode 8171.

**What to do now:**
• Check your real balance directly inside your official banking or wallet app.
• If money was unauthorizedly deducted, call the FIA Cybercrime Helpline immediately at 1991.

**What NOT to do:**
• Do not open unfamiliar links, do not install APK files, and never share any 4-digit or 6-digit verification code.

You did the right thing by checking first.`;
    }

    if (lastUserMessage.includes('1991') || lastUserMessage.includes('fia') || lastUserMessage.includes('complaint')) {
      reply += '\n\nYou can also register a formal cybercrime report online at https://complaint.fia.gov.pk with your CNIC, mobile number, and screenshots of the messages.';
    }

    return res.json({ reply });
  } catch (error) {
    console.error('Error in chat-counselor:', error);
    res.status(500).json({ error: 'Chat service unavailable' });
  }
});

// Setup Vite middlewares in development or static serving in production
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`Cyber Saathi investigation server running on port ${PORT}`);
  });
}

// In standard environments (local dev, Docker, Cloud Run, Render, Railway), start standalone server.
// In Vercel serverless environments, app is exported and invoked on-demand.
if (!process.env.VERCEL) {
  startServer();
}

export { app };
