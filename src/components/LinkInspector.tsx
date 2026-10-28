import React, { useState } from 'react';
import {
  Search,
  Link as LinkIcon,
  Clipboard,
  XCircle,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Info,
  X,
  Key,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  MessageSquarePlus,
  Send,
} from 'lucide-react';
import { Translations } from '../data/translations';
import { inspectLinkClient } from '../services/clientSecurityInspector';

export interface SourceChecked {
  name: string;
  url: string;
  accessed: boolean;
  status: string;
}

export interface AdvancedLinkResult {
  url: string;
  domain: string;
  status: 'CONFIRMED_THREAT' | 'STRONG_EVIDENCE_OF_FRAUD' | 'SUSPICIOUS' | 'NO_KNOWN_THREAT' | 'OFFICIAL_SOURCE_CORROBORATED' | 'UNABLE_TO_VERIFY';
  statusCategory: string;
  statusLabel: string;
  apiConnected: boolean;
  provider: string;
  content_summary: string;
  evidence: string[];
  sources_checked: SourceChecked[];
  checks_performed: string[];
  verified_claims: string[];
  unverified_claims: string[];
  limitations: string;
  actionRecommended: string;
  isOfficialGov: boolean;
  scanTimestamp?: string;
}

interface LinkInspectorProps {
  t: Translations;
  isRTL: boolean;
}

export const LinkInspector: React.FC<LinkInspectorProps> = ({ t, isRTL }) => {
  const [urlInput, setUrlInput] = useState<string>('');
  const [result, setResult] = useState<AdvancedLinkResult | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [copiedToast, setCopiedToast] = useState<boolean>(false);
  const [showSetupGuide, setShowSetupGuide] = useState<boolean>(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);

  // User feedback modal state
  const [showFeedbackModal, setShowFeedbackModal] = useState<boolean>(false);
  const [feedbackText, setFeedbackText] = useState<string>('');
  const [feedbackSubmitted, setFeedbackSubmitted] = useState<boolean>(false);
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState<boolean>(false);

  const handleInspect = async () => {
    const trimmed = urlInput.trim();
    if (!trimmed) {
      setErrorMessage('Please enter or paste a web address (e.g., http://... or domain.com) to investigate.');
      return;
    }
    setErrorMessage('');
    setIsScanning(true);

    try {
      const response = await fetch('/api/check-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });

      if (response.ok) {
        const data: AdvancedLinkResult = await response.json();
        setResult(data);
      } else {
        throw new Error('Server returned an error');
      }
    } catch {
      // Seamless intelligent client-side fallback for static hosts (GitHub Pages, GitLab Pages, or offline)
      const clientReport = inspectLinkClient(trimmed);
      setResult(clientReport);
    } finally {
      setIsScanning(false);
    }
  };

  const handlePaste = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        const text = await navigator.clipboard.readText();
        if (text) {
          setUrlInput(text.trim());
          setErrorMessage('');
          setCopiedToast(true);
          setTimeout(() => setCopiedToast(false), 2000);
          return;
        }
      }
    } catch {
      // Clipboard access fallback
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setResult(null);
    setErrorMessage('');
    setShowTechnicalDetails(false);
  };

  const handleSubmitFeedback = async () => {
    if (!feedbackText.trim() || isSubmittingFeedback || !result) return;
    setIsSubmittingFeedback(true);

    try {
      await fetch('/api/submit-feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetType: 'link',
          targetIdentifier: result.url,
          originalStatus: result.status,
          userCorrection: feedbackText.trim(),
        }),
      });
      setFeedbackSubmitted(true);
      setTimeout(() => {
        setShowFeedbackModal(false);
        setFeedbackSubmitted(false);
        setFeedbackText('');
      }, 2500);
    } catch (e) {
      console.error(e);
    } finally {
      setIsSubmittingFeedback(false);
    }
  };

  return (
    <section id="link-inspector" className="px-4 py-2 max-w-3xl mx-auto">
      <div className="card-tactile rounded-2xl p-4.5 bg-white shadow-xs">
        {/* Card Header */}
        <div className="flex items-start justify-between gap-2 mb-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#E6F4EA] text-[#063E28] flex items-center justify-center shrink-0 border border-[#CEEAD6]">
              <Search className="w-5 h-5 stroke-[2.5]" />
            </div>
            <div>
              <h3 className="text-base font-bold text-[#131B2E] leading-tight">
                {t.linkInspectorTitle}
              </h3>
              <p className="text-[12px] text-slate-500 leading-snug mt-0.5">
                Investigate safety, brand impersonation, and live threat databases
              </p>
            </div>
          </div>
          <span className="text-[10px] font-bold text-[#1D4ED8] bg-[#EFF6FF] border border-[#BFDBFE] px-2 py-0.5 rounded-md uppercase tracking-wider shrink-0">
            {t.liveEngineBadge}
          </span>
        </div>

        {/* URL Input Bar with Paste & Clear Buttons */}
        <div className="relative flex items-center border border-slate-300 rounded-xl bg-[#F8FAFC] focus-within:border-[#063E28] focus-within:ring-2 focus-within:ring-[#063E28]/15 transition-all p-1 mb-2">
          <div className="pl-2.5 pr-1.5 text-slate-400">
            <LinkIcon className="w-4 h-4" />
          </div>
          <input
            type="text"
            value={urlInput}
            onChange={(e) => {
              setUrlInput(e.target.value);
              if (errorMessage) setErrorMessage('');
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleInspect();
            }}
            placeholder="Paste or type suspicious link (e.g. https://...)"
            className="flex-1 min-w-0 bg-transparent text-[13px] font-mono text-[#0F172A] outline-none py-1.5 px-1"
            aria-label="Web link to inspect"
          />

          {urlInput && (
            <button
              type="button"
              onClick={handleClear}
              className="text-slate-400 hover:text-slate-600 p-1 mr-1 cursor-pointer"
              title="Clear input"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}

          <button
            type="button"
            onClick={handlePaste}
            className="flex items-center gap-1 bg-[#EEF2F6] hover:bg-slate-200 text-[#1E293B] text-xs font-semibold px-2.5 py-1.5 rounded-lg border border-slate-300/80 shrink-0 transition-colors cursor-pointer"
            title="Paste link from clipboard"
          >
            <Clipboard className="w-3.5 h-3.5 text-slate-600" />
            <span>{copiedToast ? 'Pasted!' : t.pasteBtn}</span>
          </button>
        </div>

        {/* Validation error message if empty */}
        {errorMessage && (
          <p className="text-[11.5px] text-red-600 font-medium mb-2.5 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>{errorMessage}</span>
          </p>
        )}

        {/* Primary Action Button */}
        <button
          type="button"
          onClick={handleInspect}
          disabled={isScanning}
          className="btn-tactile-primary w-full py-3 px-4 rounded-xl font-bold text-sm flex items-center justify-center gap-2 cursor-pointer mt-1"
        >
          {isScanning ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Running Deep Evidence Investigation...</span>
            </>
          ) : (
            <>
              <Search className="w-4 h-4 stroke-[2.5]" />
              <span>Investigate Link Evidence</span>
            </>
          )}
        </button>

        {/* Investigation Results Card */}
        {result && (
          <div className="mt-4 animate-in fade-in duration-200 space-y-3">
            {/* 1. Category Badge & Main Header Card */}
            <div
              className={`rounded-2xl border-2 p-4 text-left shadow-sm transition-all ${
                result.status === 'CONFIRMED_THREAT' || result.status === 'STRONG_EVIDENCE_OF_FRAUD'
                  ? 'border-red-500 bg-[#FEF2F2]'
                  : result.status === 'SUSPICIOUS'
                  ? 'border-amber-400 bg-[#FFFBEB]'
                  : result.status === 'OFFICIAL_SOURCE_CORROBORATED' || result.status === 'NO_KNOWN_THREAT'
                  ? 'border-emerald-400 bg-[#ECFDF5]'
                  : 'border-slate-300 bg-[#F8FAFC]'
              }`}
            >
              {/* Header Badge */}
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-1.5 font-extrabold text-[13px] tracking-tight">
                  {result.status === 'CONFIRMED_THREAT' || result.status === 'STRONG_EVIDENCE_OF_FRAUD' ? (
                    <>
                      <XCircle className="w-4.5 h-4.5 fill-red-600 text-white shrink-0" />
                      <span className="text-red-900">{result.statusLabel}</span>
                    </>
                  ) : result.status === 'SUSPICIOUS' ? (
                    <>
                      <AlertTriangle className="w-4.5 h-4.5 text-amber-600 shrink-0" />
                      <span className="text-amber-950">{result.statusLabel}</span>
                    </>
                  ) : result.status === 'OFFICIAL_SOURCE_CORROBORATED' || result.status === 'NO_KNOWN_THREAT' ? (
                    <>
                      <CheckCircle2 className="w-4.5 h-4.5 text-emerald-600 fill-emerald-100 shrink-0" />
                      <span className="text-emerald-950">{result.statusLabel}</span>
                    </>
                  ) : (
                    <>
                      <Info className="w-4.5 h-4.5 text-slate-600 shrink-0" />
                      <span className="text-slate-900">{result.statusLabel}</span>
                    </>
                  )}
                </div>

                <span
                  className={`text-[9.5px] font-black px-2 py-0.5 rounded-full uppercase tracking-wider ${
                    result.status === 'CONFIRMED_THREAT' || result.status === 'STRONG_EVIDENCE_OF_FRAUD'
                      ? 'bg-[#BA1A1A] text-white'
                      : result.status === 'SUSPICIOUS'
                      ? 'bg-[#D97706] text-white'
                      : result.status === 'OFFICIAL_SOURCE_CORROBORATED' || result.status === 'NO_KNOWN_THREAT'
                      ? 'bg-[#059669] text-white'
                      : 'bg-slate-700 text-white'
                  }`}
                >
                  {result.statusCategory.split('.')[0]}
                </span>
              </div>

              {/* URL Display */}
              <div className="bg-white/80 rounded-lg p-2 border border-slate-200/80 mb-2.5 font-mono text-[11px] text-slate-900 truncate">
                {result.url}
              </div>

              {/* Summary */}
              <p className="text-[12px] text-slate-800 font-medium mb-3 leading-snug">
                {result.content_summary}
              </p>

              {/* Specific Evidence Findings */}
              <div className="bg-white/90 rounded-xl p-3 border border-slate-200/70 mb-3 space-y-1.5 shadow-2xs">
                <span className="text-[11px] font-bold text-slate-900 block mb-1">
                  Specific Evidentiary Findings:
                </span>
                <ul className="space-y-1.5 text-[11.5px] text-slate-700">
                  {result.evidence.map((ev, i) => (
                    <li key={i} className="flex items-start gap-1.5 leading-snug">
                      <span
                        className={`font-black shrink-0 ${
                          result.status.includes('FRAUD') || result.status.includes('THREAT')
                            ? 'text-red-600'
                            : result.status === 'SUSPICIOUS'
                            ? 'text-amber-600'
                            : 'text-emerald-600'
                        }`}
                      >
                        •
                      </span>
                      <span>{ev}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Recommended Next Step Callout */}
              <div className="border-t border-slate-200/70 pt-2.5 flex items-baseline justify-between flex-wrap gap-1">
                <span className="text-[11.5px] font-semibold text-slate-700">Action Recommended:</span>
                <span
                  className={`text-[12px] font-bold ${
                    result.status.includes('FRAUD') || result.status.includes('THREAT')
                      ? 'text-[#BA1A1A] font-black'
                      : result.status === 'SUSPICIOUS'
                      ? 'text-amber-900'
                      : 'text-emerald-900'
                  }`}
                >
                  {result.actionRecommended}
                </span>
              </div>
            </div>

            {/* 2. Collapsible Detailed Verification Evidence */}
            <div className="border border-slate-200 rounded-xl bg-[#F8FAFC] overflow-hidden text-left">
              <button
                type="button"
                onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                className="w-full px-3.5 py-2.5 flex items-center justify-between text-xs font-bold text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <span>Sources Consulted & Investigation Record</span>
                {showTechnicalDetails ? (
                  <ChevronUp className="w-4 h-4 text-slate-500" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-slate-500" />
                )}
              </button>

              {showTechnicalDetails && (
                <div className="p-3.5 border-t border-slate-200 bg-white space-y-3 text-xs text-slate-700 animate-in fade-in duration-150">
                  {/* Sources Checked Table */}
                  <div>
                    <span className="font-bold text-slate-900 block mb-1.5">Authoritative Sources Consulted:</span>
                    <div className="space-y-1.5">
                      {result.sources_checked.map((src, i) => (
                        <div key={i} className="flex items-start justify-between gap-2 p-1.5 rounded-lg bg-slate-50 border border-slate-200/60 text-[11px]">
                          <div className="min-w-0">
                            <span className="font-semibold text-slate-900 block truncate">{src.name}</span>
                            <span className="text-slate-500 text-[10px] truncate block">{src.url}</span>
                          </div>
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                              src.accessed
                                ? src.status.includes('match')
                                  ? 'bg-red-100 text-red-700'
                                  : 'bg-emerald-100 text-emerald-800'
                                : 'bg-slate-200 text-slate-600'
                            }`}
                          >
                            {src.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Checks Performed */}
                  <div>
                    <span className="font-bold text-slate-900 block mb-1">Checks Completed:</span>
                    <ul className="list-disc pl-4 space-y-0.5 text-[11px] text-slate-600">
                      {result.checks_performed.map((chk, i) => (
                        <li key={i}>{chk}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Limitations & Uncertainty */}
                  {result.limitations && (
                    <div className="bg-amber-50/70 border border-amber-200/80 rounded-lg p-2.5 text-[11px] text-amber-900">
                      <strong className="block mb-0.5">Known Limitations:</strong>
                      {result.limitations}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* 3. Feedback / False-Positive Reporting Trigger */}
            <div className="flex items-center justify-between px-1 text-[11px] text-slate-500">
              <span>Notice an inaccurate classification?</span>
              <button
                type="button"
                onClick={() => setShowFeedbackModal(true)}
                className="text-[#063E28] hover:underline font-bold flex items-center gap-1 cursor-pointer"
              >
                <MessageSquarePlus className="w-3.5 h-3.5" />
                <span>Report for Review</span>
              </button>
            </div>
          </div>
        )}

        {/* Feedback Modal */}
        {showFeedbackModal && (
          <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="bg-white rounded-2xl max-w-sm w-full p-4.5 shadow-xl border border-slate-200 text-left animate-in zoom-in-95">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-bold text-slate-900">Report Inaccurate Classification</h4>
                <button
                  type="button"
                  onClick={() => setShowFeedbackModal(false)}
                  className="text-slate-400 hover:text-slate-600"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <p className="text-xs text-slate-600 mb-3 leading-relaxed">
                Cyber Saathi avoids falsely accusing genuine websites. If this assessment was incorrect, please share what this website actually is.
              </p>

              {feedbackSubmitted ? (
                <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-emerald-800 text-xs font-semibold text-center">
                  Thank you! Your feedback report has been recorded for review.
                </div>
              ) : (
                <>
                  <textarea
                    rows={3}
                    value={feedbackText}
                    onChange={(e) => setFeedbackText(e.target.value)}
                    placeholder="e.g. This is my university department portal or a verified local news blog..."
                    className="w-full bg-[#F8FAFC] border border-slate-300 rounded-xl p-2.5 text-xs text-slate-900 outline-none focus:border-[#063E28] mb-3"
                  />
                  <div className="flex items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setShowFeedbackModal(false)}
                      className="px-3 py-1.5 text-xs font-semibold text-slate-600 hover:text-slate-800"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={handleSubmitFeedback}
                      disabled={!feedbackText.trim() || isSubmittingFeedback}
                      className="btn-tactile-primary px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer disabled:opacity-50"
                    >
                      <Send className="w-3 h-3" />
                      <span>{isSubmittingFeedback ? 'Submitting...' : 'Submit Report'}</span>
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
