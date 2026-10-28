import fs from 'fs';
import { URL } from 'url';
import { validateAndSanitizeUrl, safeRetrievePageInfo, isPrivateOrReservedIp, type PageRetrievalResult } from './investigationService.ts';

export interface BrowserInvestigationResult {
  executedWithBrowser: boolean;
  retrieved: boolean;
  httpStatus?: number;
  finalUrl?: string;
  title?: string;
  description?: string;
  visibleText?: string;
  redirectsTraversed: string[];
  requiresJavaScript: boolean;
  failureReason?: string;
  securityObservations: string[];
  investigationMethod: 'isolated_headless_chromium' | 'safe_http_retrieval';
}

const CANDIDATE_CHROMIUM_PATHS = [
  process.env.CHROMIUM_PATH,
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
  '/ms-playwright/chromium_headless_shell-1247/chrome-headless-shell-linux64/chrome-headless-shell',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
].filter(Boolean) as string[];

export function getChromiumExecutablePath(): string | null {
  for (const candidate of CANDIDATE_CHROMIUM_PATHS) {
    try {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    } catch {
      // Ignore filesystem access exceptions
    }
  }
  return null;
}

// Check if headless Chromium executable is available in this environment
export function isHeadlessChromiumSupported(): boolean {
  return getChromiumExecutablePath() !== null;
}

/**
 * Investigates a public webpage using an isolated server-side Headless Chromium session
 * or falls back to safe server-side HTTP retrieval if Chromium is unavailable or fails.
 */
export async function investigatePublicWebpage(targetUrl: string): Promise<BrowserInvestigationResult> {
  const securityObservations: string[] = [];
  const redirectsTraversed: string[] = [];

  // Step 1: Pre-navigation SSRF, private network, and URL scheme validation
  const preNavCheck = await validateAndSanitizeUrl(targetUrl);
  if (!preNavCheck.valid || !preNavCheck.normalizedUrl) {
    return {
      executedWithBrowser: false,
      retrieved: false,
      redirectsTraversed: [],
      requiresJavaScript: false,
      failureReason: preNavCheck.reason || 'URL violates safe browsing boundaries.',
      securityObservations: ['Pre-navigation security check blocked destination (SSRF / private network defense).'],
      investigationMethod: 'safe_http_retrieval',
    };
  }

  const normalizedTarget = preNavCheck.normalizedUrl;
  redirectsTraversed.push(normalizedTarget);

  // If Chromium headless shell is available, run isolated browser investigation
  if (isHeadlessChromiumSupported()) {
    let browser: any = null;
    let context: any = null;

    try {
      const { chromium } = await import('playwright-core');

      browser = await chromium.launch({
        executablePath: getChromiumExecutablePath()!,
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--disable-extensions',
          '--disable-background-networking',
          '--disable-sync',
          '--disable-default-apps',
          '--mute-audio',
          '--no-first-run',
        ],
      });

      // Requirement 6: Isolated browser context destroyed after each request
      context = await browser.newContext({
        permissions: [],
        acceptDownloads: false,
        javaScriptEnabled: true,
        bypassCSP: false,
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberSaathiCivicInspector/2.6',
        viewport: { width: 1280, height: 800 },
        ignoreHTTPSErrors: false,
      });

      const page = await context.newPage();
      page.setDefaultNavigationTimeout(8000); // 8s navigation timeout
      page.setDefaultTimeout(8000);

      // Requirement 7: Prevent file downloads
      page.on('download', (download: any) => {
        download.cancel().catch(() => {});
      });

      // Requirement 1 & 2: Route interception - block loopback, private IPs, cloud metadata, and heavy media
      await page.route('**/*', async (route: any) => {
        const reqUrl = route.request().url();
        try {
          const parsed = new URL(reqUrl);
          // Block non-HTTP protocols
          if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return route.abort('blockedbyclient');
          }

          const host = parsed.hostname.toLowerCase();
          // Fast local host and private IP check across IPv4/IPv6 and link-local ranges
          if (
            host === 'localhost' ||
            host.endsWith('.local') ||
            host.endsWith('.internal') ||
            host === '::1' ||
            host === '[::1]' ||
            host === '0.0.0.0' ||
            isPrivateOrReservedIp(host)
          ) {
            securityObservations.push(`Blocked internal navigation request to: ${host}`);
            return route.abort('blockedbyclient');
          }

          // Abort heavy media, fonts, images to protect memory and speed up inspection
          const resourceType = route.request().resourceType();
          if (['image', 'media', 'font', 'stylesheet'].includes(resourceType)) {
            return route.abort();
          }

          return route.continue();
        } catch {
          return route.abort('blockedbyclient');
        }
      });

      // Track server redirects securely
      page.on('response', (response: any) => {
        const status = response.status();
        const respUrl = response.url();
        if ([301, 302, 303, 307, 308].includes(status)) {
          if (!redirectsTraversed.includes(respUrl)) {
            redirectsTraversed.push(respUrl);
          }
        }
      });

      // Requirement 8: Read-only observation. Never submit forms or enter credentials.
      const navigationResponse = await page.goto(normalizedTarget, {
        waitUntil: 'domcontentloaded',
        timeout: 8000,
      });

      const httpStatus = navigationResponse ? navigationResponse.status() : 200;
      const finalUrl = page.url();
      if (!redirectsTraversed.includes(finalUrl)) {
        redirectsTraversed.push(finalUrl);
      }

      // Validate final landed URL against SSRF (in case of client-side or meta redirect)
      const finalCheck = await validateAndSanitizeUrl(finalUrl);
      if (!finalCheck.valid) {
        return {
          executedWithBrowser: true,
          retrieved: false,
          httpStatus,
          redirectsTraversed,
          requiresJavaScript: true,
          failureReason: `Final redirect destination blocked: ${finalCheck.reason}`,
          securityObservations: ['Landing URL after navigation violated SSRF boundary.'],
          investigationMethod: 'isolated_headless_chromium',
        };
      }

      const pageTitle = (await page.title()) || undefined;

      // Extract description meta tag if available
      let description: string | undefined;
      try {
        description =
          (await page.$eval('meta[name="description"]', (el: any) => el.content).catch(() => undefined)) || undefined;
      } catch {
        description = undefined;
      }

      // Requirement 5 & 9: Extract visible text, capped at 4000 characters and treated as untrusted
      let visibleText = '';
      try {
        visibleText = await page.innerText('body');
        visibleText = visibleText.replace(/\s+/g, ' ').trim().slice(0, 4000);
      } catch {
        visibleText = '';
      }

      // Check for password inputs or credential forms
      let hasLoginForm = false;
      try {
        hasLoginForm = await page.$eval(
          'input[type="password"], input[name*="otp"], input[name*="pin"], input[name*="cnic"]',
          () => true
        ).catch(() => false);
      } catch {
        hasLoginForm = false;
      }

      if (hasLoginForm) {
        securityObservations.push('Page contains sensitive input fields (password, PIN, or CNIC entry form).');
      }

      return {
        executedWithBrowser: true,
        retrieved: true,
        httpStatus,
        finalUrl,
        title: pageTitle,
        description,
        visibleText,
        redirectsTraversed,
        requiresJavaScript: true,
        securityObservations,
        investigationMethod: 'isolated_headless_chromium',
      };
    } catch (browserErr: any) {
      securityObservations.push(`Chromium execution encounter: ${browserErr.message}. Falling back to safe HTTP inspection.`);
    } finally {
      if (context) {
        await context.close().catch(() => {});
      }
      if (browser) {
        await browser.close().catch(() => {});
      }
    }
  }

  // Fallback: Safe Server-Side HTTP Page Retrieval
  const httpResult: PageRetrievalResult = await safeRetrievePageInfo(normalizedTarget);
  return {
    executedWithBrowser: false,
    retrieved: httpResult.retrieved,
    httpStatus: httpResult.httpStatus,
    finalUrl: httpResult.finalUrl,
    title: httpResult.title,
    description: httpResult.description,
    visibleText: httpResult.textExcerpt,
    redirectsTraversed: httpResult.finalUrl ? [normalizedTarget, httpResult.finalUrl] : [normalizedTarget],
    requiresJavaScript: Boolean(httpResult.requiresJavaScript),
    failureReason: httpResult.failureReason,
    securityObservations,
    investigationMethod: 'safe_http_retrieval',
  };
}
