# 🛡️ Sindh Cyber Saathi (سنڌ سائبر ساٿي / سندھ سائبر ساتھی)

> **Official Civic Cyber Defense Platform — Sindh Youth Innovation Challenge**
>
> An evidence-based cybersecurity web application designed to help citizens across Sindh and Pakistan detect phishing links, analyze suspicious screenshots and SMS alerts, and prevent financial fraud before clicking.

---

## 🌟 Key Features

1. **🔗 Check a Link (Instant Link Inspector)**
   - Live threat detection powered by **Google Safe Browsing v4**.
   - Heuristic spoofing analysis (detects homograph attacks, typosquatting, deceptive subdomains, and suspicious TLDs like `.xyz`, `.top`, `.buzz`).
   - Strict SSRF (Server-Side Request Forgery) protection against private IPs (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`, cloud metadata services).
   - Automated authentication against the verified civic registry for official government domains (`.gov.pk` and `.gos.pk`).

2. **📸 Check a Screenshot (Forensic Image & SMS Analyzer)**
   - Client-side image validation (5 MB upload safety limit).
   - Forensic OCR feature extraction powered by **Google Gemini 3.5 Flash** with deterministic extraction parameters.
   - Built-in QR Code decoder (`jsQR`) to extract hidden URLs from scam payment slips and lottery images.
   - Honest evidentiary standard: Never claims authenticity solely from logos, names, or HTTPS certificates.

3. **💬 AI Cyber Defense Counselor**
   - Interactive, localized guidance on how to report scams, freeze compromised bank accounts, and preserve digital evidence.
   - High-demand resilient fallback chain (`gemini-3.5-flash` → `gemini-3.5-flash-lite` → `gemini-3.6-flash`).

4. **🌐 Full Trilingual Support**
   - Seamless one-click switching between **English (EN)**, **Sindhi (سنڌي)**, and **Urdu (اردو)**.
   - Native typography with full RTL (Right-to-Left) bidirectional layout support.

5. **🚨 Emergency FIA 1991 Integration**
   - Instant guidance on the **Golden Hour Protocol** for freezing unauthorized transactions via 1Link and State Bank of Pakistan (SBP).

---

## 🏗️ Architecture & Project Structure

The project is built as a production-grade full-stack TypeScript application:

```
sindh-cyber-saathi/
├── api/
│   └── index.ts                 # Vercel serverless entry point
├── public/                      # Static assets & downloadable project archive
├── src/
│   ├── components/              # Tactile, mobile-friendly UI components
│   │   ├── Header.tsx           # Branding & 3-way language switcher (EN / SD / UR)
│   │   ├── ProminentActionSelector.tsx # Dual prominent action cards
│   │   ├── LinkInspector.tsx    # Live URL scanner with deep evidence cards
│   │   ├── ScreenshotAnalyzer.tsx # 5-question visual forensic inspector
│   │   ├── CyberSaathiChatbot.tsx # AI counseling modal
│   │   ├── HelplineBanner.tsx   # FIA 1991 emergency alert banner
│   │   ├── ThreatFeed.tsx       # Live feed of active scam patterns in Sindh
│   │   ├── CyberHygieneRules.tsx # 3 essential rules for citizens
│   │   └── BottomNav.tsx        # Responsive mobile navigation
│   ├── data/
│   │   ├── translations.ts      # Complete EN, SD, and UR dictionary
│   │   └── threatFeedData.ts    # Curated intelligence on active scam campaigns
│   └── services/
│       ├── sharedEvidencePipeline.ts # Unified deterministic decision engine
│       ├── investigationService.ts   # Safe Browsing API, SSRF gateway, civic registry
│       ├── browserInvestigationService.ts # Dynamic Chromium / Safe HTTP retrieval
│       ├── qrService.ts              # QR matrix decoding pipeline
│       └── diagnosticLogger.ts       # Structured diagnostic traces
├── server.ts                    # Express API server & Vite development proxy
├── vercel.json                  # Vercel deployment configuration
├── package.json                 # Project dependencies & scripts
├── tsconfig.json                # TypeScript compiler configuration
├── vite.config.ts               # Vite frontend bundler configuration
└── .env.example                 # Environment variable templates (no secrets)
```

---

## 🚀 Quick Start (Local Setup)

### Prerequisites
- **Node.js**: Version 18.x or higher (v20+ recommended).
- **npm** or **bun** or **yarn**.

### Step 1: Clone or Extract the Project
```bash
git clone <your-github-repo-url>
cd sindh-cyber-saathi
```
*(Or unzip the downloaded `sindh-cyber-saathi-project.zip` file and open a terminal inside the folder).*

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Configure Environment Variables
Copy `.env.example` to create your local `.env` file:
```bash
cp .env.example .env
```
Open `.env` and add your API keys:
```env
# Required for AI Counselor and Screenshot OCR Analysis:
GEMINI_API_KEY="your-gemini-api-key-here"

# Optional (free) for live Google Safe Browsing threat lists:
SAFE_BROWSING_API_KEY="your-google-safe-browsing-key-here"

# Server Port:
PORT=3000
```
> **How to get free API keys:**
> - **Gemini API Key**: Free at [Google AI Studio](https://aistudio.google.com/app/apikey).
> - **Safe Browsing Key**: Free in [Google Cloud Console](https://console.cloud.google.com/) under **APIs & Services → Enable Safe Browsing API**.

### Step 4: Run the Development Server
```bash
npm run dev
```
Open your browser and navigate to:
```
http://localhost:3000
```

---

## 🧪 Testing & Quality Checks

Run the automated test suite covering 68 adversarial stress tests, edge cases, negative controls, and SSRF boundary conditions:
```bash
npm test
```

Run TypeScript type-checking without emitting:
```bash
npm run lint
```

Build the production bundle:
```bash
npm run build
```

---

## ☁️ Deployment Guide

### Option 1: Deploying to Vercel (Step-by-Step)

The project includes built-in Vercel configuration (`vercel.json` and `api/index.ts`).

#### Important Architecture Notes for Vercel:
1. **Serverless Execution**: Vercel executes the backend as serverless functions with a 50 MB zip limit and maximum execution timeout (10s on hobby plans).
2. **Headless Browser Compatibility**: Full Playwright Chromium binaries (~150 MB) cannot fit inside a standard Vercel serverless bundle. **Sindh Cyber Saathi handles this automatically:**
   - The application automatically detects that Chromium is not available in the Vercel environment.
   - It gracefully falls back to the **Safe HTTP Retrieval Gateway** (`safeHttpFetchWebpage`).
   - Webpage title, description, SSL certificates, headers, and official registries are still inspected safely with zero crashes!

#### Steps to Deploy to Vercel:
1. Push your repository to **GitHub**.
2. Go to [vercel.com](https://vercel.com/) and sign in.
3. Click **"Add New"** → **"Project"** and select your GitHub repository.
4. In **Project Settings**:
   - **Framework Preset**: Vite
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
5. Under **Environment Variables**, add:
   - `GEMINI_API_KEY`: Your Gemini API key
   - `SAFE_BROWSING_API_KEY`: Your Safe Browsing API key (optional)
6. Click **Deploy**. Your app will be live within 1–2 minutes!

---

### Option 2: Deploying to Render / Railway / Google Cloud Run (Recommended for 100% Full Features)

For full-stack Node.js environments that support long-running processes and headless browsers:

1. Connect your GitHub repository to **Render**, **Railway**, or **Google Cloud Run**.
2. Set the build and start commands:
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start` (or `npx tsx server.ts`)
3. Add environment variables:
   - `GEMINI_API_KEY`
   - `SAFE_BROWSING_API_KEY`
4. The service will run as an always-on full-stack service with full Playwright Chromium capabilities enabled.

---

### Option 3: Deploying to GitHub Pages (Static Hosting)

The project is pre-configured for GitHub Pages:
- **Relative Asset Base (`base: './'`)**: Resolves scripts and styles correctly even when hosted in a repository subpath (e.g. `https://<username>.github.io/<repo-name>/`).
- **`.nojekyll`**: Included in `public/` and `dist/` to prevent GitHub's Jekyll engine from ignoring assets.
- **`404.html`**: Automatically generated on build so refreshing or direct routing loads properly.
- **Client Fallback & ErrorBoundary**: Ensures the UI never crashes or displays a blank screen if backend APIs are offline.

#### How to Deploy via GitHub Actions (Recommended):
1. Push your code to your GitHub repository (branch `main`).
2. On GitHub, navigate to **Settings** → **Pages**.
3. Under **Build and deployment** → **Source**, select **GitHub Actions**.
4. Push a new commit or go to the **Actions** tab and trigger the **"Deploy to GitHub Pages"** workflow.
5. In ~1 minute, your site will be live at `https://<username>.github.io/<repository-name>/`.

#### Manual Deployment via gh-pages branch:
```bash
npm run build
npx gh-pages -d dist
```

---

## 🔒 Security & Privacy Commitments

- **No Secret Leakage**: API keys and service tokens are kept exclusively in server-side memory and are never sent to the client browser.
- **Ephemeral Processing**: Uploaded screenshots are analyzed in-memory and discarded. No private citizen photos or messages are stored on persistent disks.
- **Local-First Verification**: Where possible, URL parsing, regex heuristics, and client-side validations run directly in the user's browser before requesting backend services.

---

## 📜 License
Distributed under the **Apache-2.0 License**. Developed for the **Sindh Youth Innovation Challenge**.
