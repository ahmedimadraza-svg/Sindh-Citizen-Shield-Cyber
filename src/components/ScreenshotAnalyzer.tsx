import React, { useState, useRef } from 'react';
import {
  ScanLine,
  Search,
  Lock,
  X,
  UploadCloud,
  Image as ImageIcon,
  AlertTriangle,
  ShieldAlert,
  PhoneCall,
  CheckCircle2,
  FileText,
  HelpCircle,
  Eye,
  CheckSquare,
  ChevronDown,
  ChevronUp,
  MessageSquarePlus,
  Send,
  ExternalLink,
  XCircle,
  Info,
} from 'lucide-react';
import { Translations } from '../data/translations';

interface QuestionItem {
  answered: boolean;
  details?: string;
  findings?: string;
}

interface FourQuestions {
  is_readable: QuestionItem;
  scam_indicators_present: QuestionItem;
  visual_manipulation_detected: QuestionItem;
  independently_verified: QuestionItem;
}

interface FiveQuestions {
  questionA_messageContent: { answered: boolean; summary: string; details?: string };
  questionB_suspiciousInstructions: { answered: boolean; summary: string; findings?: string };
  questionC_destinationUrl: { answered: boolean; summary: string; findings?: string };
  questionD_officialCorroboration: { answered: boolean; summary: string; findings?: string };
  questionE_senderAuthenticated: { answered: boolean; summary: string; findings?: string };
}

interface ScreenshotEvidenceResult {
  content_summary: string;
  document_type: string;
  apparent_organization: string;
  risk_status: string;
  status_label: string;
  badge_color: 'red' | 'amber' | 'emerald' | 'slate';
  verdict?: string;
  four_questions?: FourQuestions;
  five_questions?: FiveQuestions;
  evidence: string[];
  sources_checked?: Array<{ name: string; url: string; status: string }>;
  verified_claims?: string[];
  unverified_claims?: string[];
  limitations?: string;
  recommended_next_step: string;
  emergency_helpline_needed?: boolean;
}

interface ScreenshotAnalyzerProps {
  t: Translations;
  isRTL: boolean;
}

export const ScreenshotAnalyzer: React.FC<ScreenshotAnalyzerProps> = ({ t, isRTL }) => {
  const [uploadedFile, setUploadedFile] = useState<{
    file: File;
    previewUrl: string;
    base64: string;
    name: string;
    size: string;
  } | null>(null);

  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [result, setResult] = useState<ScreenshotEvidenceResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [additionalText, setAdditionalText] = useState<string>('');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);

  // User feedback modal state
  const [showFeedbackModal, setShowFeedbackModal] = useState<boolean>(false);
  const [feedbackText, setFeedbackText] = useState<string>('');
  const [feedbackSubmitted, setFeedbackSubmitted] = useState<boolean>(false);
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setErrorMessage('Please upload a valid image file (PNG, JPG, JPEG, or WEBP).');
      return;
    }

    // Limit upload file size to 5 MB
    const MAX_FILE_SIZE = 5 * 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
      setErrorMessage('File size exceeds the 5 MB limit. Please upload a smaller screenshot or photo.');
      return;
    }

    setErrorMessage('');
    const previewUrl = URL.createObjectURL(file);
    const sizeStr = (file.size / 1024).toFixed(1) + ' KB';

    const reader = new FileReader();
    reader.onloadend = () => {
      const base64 = reader.result as string;
      setUploadedFile({
        file,
        previewUrl,
        base64,
        name: file.name,
        size: sizeStr,
      });
      setResult(null);
    };
    reader.readAsDataURL(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleRemoveFile = () => {
    if (uploadedFile?.previewUrl) {
      URL.revokeObjectURL(uploadedFile.previewUrl);
    }
    setUploadedFile(null);
    setResult(null);
    setErrorMessage('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAnalyze = async () => {
    if (!uploadedFile) {
      setErrorMessage('Please select or upload a screenshot first.');
      return;
    }

    setIsAnalyzing(true);
    setErrorMessage('');

    try {
      const response = await fetch('/api/analyze-screenshot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          imageBase64: uploadedFile.base64,
          mimeType: uploadedFile.file.type,
          fileName: uploadedFile.name,
          manualText: additionalText.trim() || undefined,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setResult(data);
      } else {
        throw new Error('Server returned error status');
      }
    } catch {
      // Inaccessible sources or failed services must produce an explicit UNABLE TO VERIFY result
      setResult({
        content_summary: 'Unable to communicate with the verification backend service. Please check network connectivity and retry.',
        document_type: 'Digital Screenshot',
        apparent_organization: 'Unverified Communication',
        risk_status: 'UNABLE TO VERIFY',
        status_label: 'UNABLE TO VERIFY (SERVICE UNAVAILABLE)',
        badge_color: 'slate',
        verdict: 'UNABLE TO VERIFY',
        four_questions: {
          is_readable: {
            answered: false,
            details: 'Could not communicate with server extraction service.',
          },
          scam_indicators_present: {
            answered: false,
            findings: 'Inspection could not complete due to network or service error.',
          },
          visual_manipulation_detected: {
            answered: false,
            findings: 'Forensic evaluation unavailable.',
          },
          independently_verified: {
            answered: false,
            findings: 'Backend service unreachable.',
          },
        },
        evidence: [
          'Verification service was unreachable or encountered an unexpected network timeout.',
          'No forensic evidence could be collected.',
        ],
        verified_claims: [],
        unverified_claims: ['Entire submission is unverified due to service failure.'],
        limitations: 'Failed service request. Cannot evaluate screenshot safety without backend connectivity.',
        recommended_next_step: 'Please check your internet connection and submit the screenshot again.',
        emergency_helpline_needed: false,
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSubmitFeedback = async () => {
    if (!feedbackText.trim() || isSubmittingFeedback || !result || !uploadedFile) return;
    setIsSubmittingFeedback(true);

    try {
      await fetch('/api/submit-feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetType: 'screenshot',
          targetIdentifier: uploadedFile.name,
          originalStatus: result.status_label,
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
    <section id="screenshot-analyzer" className="px-4 py-2 max-w-3xl mx-auto">
      <div className="card-tactile rounded-2xl p-4.5 bg-white shadow-xs">
        {/* Header */}
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-xl bg-[#E6F4EA] text-[#063E28] flex items-center justify-center shrink-0 border border-[#CEEAD6]">
            <ScanLine className="w-5 h-5 stroke-[2.5]" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-base font-bold text-[#131B2E] leading-tight">
              {t.screenshotTitle}
            </h3>
            <p className="text-[12px] text-slate-500 leading-snug mt-0.5">
              Evidence-based inspection for notices, SMS alerts, and payment claims
            </p>
          </div>
        </div>

        {/* Upload Drop Zone */}
        {!uploadedFile ? (
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition-all mb-3 ${
              isDragging
                ? 'border-[#063E28] bg-[#E6F4EA]/50'
                : 'border-slate-300 hover:border-[#063E28] bg-[#F8FAFC]'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept="image/*"
              className="hidden"
            />
            <div className="w-12 h-12 rounded-full bg-[#E6F4EA] text-[#063E28] flex items-center justify-center mx-auto mb-2.5 border border-[#CEEAD6]">
              <UploadCloud className="w-6 h-6 stroke-[2]" />
            </div>
            <h4 className="text-sm font-bold text-[#131B2E] mb-1">
              Upload Screenshot or Notice Photo
            </h4>
            <p className="text-xs text-slate-500 max-w-xs mx-auto mb-2">
              Tap to browse images or drop screenshot here (PNG, JPG, WEBP)
            </p>
            <span className="inline-block px-3 py-1 bg-white border border-slate-200 rounded-lg text-xs font-semibold text-[#063E28] shadow-2xs">
              Select Image File
            </span>
          </div>
        ) : (
          /* Uploaded Preview Card */
          <div className="border-2 border-dashed border-[#063E28]/40 rounded-xl p-3 bg-[#F8FAFC] mb-3">
            <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-xs mb-2">
              <div className="flex items-center justify-between mb-2 pb-2 border-b border-slate-100">
                <span className="text-xs font-bold text-slate-700 flex items-center gap-1.5 truncate">
                  <ImageIcon className="w-4 h-4 text-[#063E28]" />
                  <span className="truncate max-w-[200px]">{uploadedFile.name}</span>
                </span>
                <button
                  type="button"
                  onClick={handleRemoveFile}
                  className="w-6 h-6 rounded-full bg-slate-100 hover:bg-red-50 hover:text-red-600 flex items-center justify-center text-slate-500 transition-colors cursor-pointer"
                  title="Remove uploaded image"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Render actual image preview */}
              <div className="relative rounded-lg overflow-hidden bg-slate-900/5 max-h-56 flex items-center justify-center border border-slate-200/80">
                <img
                  src={uploadedFile.previewUrl}
                  alt="Uploaded suspicious screenshot"
                  className="max-h-52 w-auto object-contain rounded"
                />
              </div>

              <div className="flex items-center justify-between text-[11px] pt-2 text-slate-500 font-medium">
                <span>Size: {uploadedFile.size}</span>
                <span className="text-[#006C49] font-bold flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
                  Ready for forensic investigation
                </span>
              </div>
            </div>

            {/* Change image trigger */}
            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="text-xs font-bold text-[#063E28] hover:underline cursor-pointer flex items-center gap-1"
              >
                <UploadCloud className="w-3.5 h-3.5" />
                <span>Upload a different image</span>
              </button>
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept="image/*"
                className="hidden"
              />
            </div>
          </div>
        )}
        {/* Optional Manual Text / Link Assist */}
        {uploadedFile && (
          <div className="mb-3">
            <label className="block text-[11px] font-semibold text-slate-600 mb-1">
              Visible link or message text in screenshot (optional):
            </label>
            <input
              type="text"
              value={additionalText}
              onChange={(e) => setAdditionalText(e.target.value)}
              placeholder="e.g. bit.ly/gcash-0ne or free-recharge.buzz/claim"
              className="w-full text-xs px-3 py-2 border border-slate-300 rounded-lg focus:outline-hidden focus:border-[#063E28] bg-white text-slate-800 placeholder-slate-400"
            />
          </div>
        )}

        {/* Validation error if no file */}
        {errorMessage && (
          <p className="text-[11.5px] text-red-600 font-medium mb-2.5 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>{errorMessage}</span>
          </p>
        )}

        {/* Primary Action Button */}
        <button
          type="button"
          onClick={handleAnalyze}
          disabled={isAnalyzing || !uploadedFile}
          className={`w-full py-3 px-4 rounded-xl font-bold text-sm flex items-center justify-center gap-2 cursor-pointer mb-2.5 transition-all ${
            uploadedFile
              ? 'btn-tactile-primary'
              : 'bg-slate-200 text-slate-400 cursor-not-allowed border border-slate-300'
          }`}
        >
          {isAnalyzing ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Investigating Visual Evidence...</span>
            </>
          ) : (
            <>
              <Search className="w-4 h-4 stroke-[2.5]" />
              <span>Investigate Screenshot Claims</span>
            </>
          )}
        </button>

        {/* Privacy Notice Banner */}
        <div className="flex items-center gap-2 text-[11px] text-slate-600 bg-[#F1F5F9] rounded-lg p-2 border border-slate-200">
          <Lock className="w-3.5 h-3.5 text-[#006C49] shrink-0" />
          <span className="leading-tight">
            Evidence-based inspection. Ephemeral processing; images are not retained on servers.
          </span>
        </div>

        {/* Investigation Findings Card */}
        {result && (
          <div className="mt-4 animate-in fade-in duration-200 space-y-3 text-left">
            {/* Main Assessment Header Card */}
            <div
              className={`rounded-2xl border-2 p-4 shadow-sm ${
                result.badge_color === 'red'
                  ? 'border-red-400 bg-[#FEF2F2]'
                  : result.badge_color === 'amber'
                  ? 'border-amber-400 bg-[#FFFBEB]'
                  : result.badge_color === 'emerald'
                  ? 'border-emerald-400 bg-[#ECFDF5]'
                  : 'border-slate-300 bg-[#F8FAFC]'
              }`}
            >
              {/* Header Label Row */}
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-1.5 font-extrabold text-[13px] tracking-tight">
                  {result.badge_color === 'red' ? (
                    <XCircle className="w-4.5 h-4.5 fill-red-600 text-white shrink-0" />
                  ) : result.badge_color === 'amber' ? (
                    <AlertTriangle className="w-4.5 h-4.5 text-amber-600 shrink-0" />
                  ) : result.badge_color === 'emerald' ? (
                    <CheckCircle2 className="w-4.5 h-4.5 text-emerald-600 fill-emerald-100 shrink-0" />
                  ) : (
                    <Info className="w-4.5 h-4.5 text-slate-600 shrink-0" />
                  )}
                  <span className="text-slate-900">{result.status_label}</span>
                </div>

                <span
                  className={`text-[9px] font-black px-2 py-0.5 rounded-full uppercase tracking-wider ${
                    result.badge_color === 'red'
                      ? 'bg-[#BA1A1A] text-white'
                      : result.badge_color === 'amber'
                      ? 'bg-[#D97706] text-white'
                      : result.badge_color === 'emerald'
                      ? 'bg-[#059669] text-white'
                      : 'bg-slate-700 text-white'
                  }`}
                >
                  {result.document_type || 'DOCUMENT'}
                </span>
              </div>

              {/* Objective Content Summary (Explains what screenshot claims before judging) */}
              <div className="bg-white/90 rounded-xl p-3 border border-slate-200 mb-3 shadow-2xs">
                <span className="text-[10.5px] font-bold text-slate-500 uppercase tracking-wide block mb-1">
                  Content Summary & Claim:
                </span>
                <p className="text-[12px] text-slate-800 leading-relaxed font-normal">
                  {result.content_summary}
                </p>
                {result.apparent_organization && (
                  <span className="inline-block text-[11px] font-bold text-slate-600 bg-slate-100 px-2 py-0.5 rounded mt-2">
                    Claimed Organization: {result.apparent_organization}
                  </span>
                )}
              </div>

              {/* Core Evidentiary Questions Audit */}
              <div className="space-y-2 mb-3">
                <span className="text-[11px] font-extrabold text-slate-900 block">
                  {result.five_questions ? 'Investigation of 5 Distinct Questions:' : 'Investigation of 4 Core Questions:'}
                </span>

                {result.five_questions ? (
                  <>
                    {/* Question A: Message Content & Claims */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <Eye className="w-3.5 h-3.5 text-[#063E28]" />
                        <span>A. What does the message actually say?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.five_questions.questionA_messageContent.summary}
                      </p>
                    </div>

                    {/* Question B: Suspicious Instructions / Scam Demands */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <ShieldAlert
                          className={`w-3.5 h-3.5 ${
                            result.badge_color === 'red' ? 'text-red-600' : 'text-emerald-600'
                          }`}
                        />
                        <span>B. Suspicious instructions, payment demands, or threats?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.five_questions.questionB_suspiciousInstructions.summary}
                      </p>
                    </div>

                    {/* Question C: Destination URL & Hostname */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <HelpCircle className="w-3.5 h-3.5 text-blue-600" />
                        <span>C. Destination URL and actual hostname?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.five_questions.questionC_destinationUrl.findings || result.five_questions.questionC_destinationUrl.summary}
                      </p>
                    </div>

                    {/* Question D: Official Source Corroboration */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <CheckSquare className="w-3.5 h-3.5 text-amber-600" />
                        <span>D. Is claim corroborated by an accessed official source?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.five_questions.questionD_officialCorroboration.summary}
                      </p>
                    </div>

                    {/* Question E: Sender Authentication */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <Lock className="w-3.5 h-3.5 text-slate-600" />
                        <span>E. Can original sender identity be authenticated?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        <span className="font-semibold text-slate-700 block">{result.five_questions.questionE_senderAuthenticated.summary}</span>
                        <span>{result.five_questions.questionE_senderAuthenticated.findings}</span>
                      </p>
                    </div>
                  </>
                ) : (
                  <>
                    {/* 1. Is it readable? */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <Eye className="w-3.5 h-3.5 text-[#063E28]" />
                        <span>1. Is the Content Readable?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.four_questions?.is_readable?.details || 'Text and layout are readable.'}
                      </p>
                    </div>

                    {/* 2. Does it show scam indicators? */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <ShieldAlert
                          className={`w-3.5 h-3.5 ${
                            result.four_questions?.scam_indicators_present?.answered ? 'text-red-600' : 'text-emerald-600'
                          }`}
                        />
                        <span>2. Concrete Scam Indicators?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.four_questions?.scam_indicators_present?.findings ||
                          'No obvious scam indicators identified.'}
                      </p>
                    </div>

                    {/* 3. Visual manipulation & provenance check */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <HelpCircle className="w-3.5 h-3.5 text-blue-600" />
                        <span>3. Visual Manipulation & Provenance Check</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.four_questions?.visual_manipulation_detected?.findings ||
                          'No obvious optical tampering detected. Note that camera EXIF and cryptographic provenance cannot be verified from compressed image uploads.'}
                      </p>
                    </div>

                    {/* 4. Independently verified? */}
                    <div className="bg-white/80 rounded-lg p-2.5 border border-slate-200/80 text-[11.5px] space-y-0.5">
                      <div className="flex items-center gap-1.5 font-bold text-slate-900">
                        <CheckSquare className="w-3.5 h-3.5 text-amber-600" />
                        <span>4. Can It Be Independently Verified?</span>
                      </div>
                      <p className="text-slate-600 text-[11px] pl-5">
                        {result.four_questions?.independently_verified?.findings ||
                          'General format is consistent with public standards, but private records cannot be confirmed from image alone.'}
                      </p>
                    </div>
                  </>
                )}
              </div>

              {/* Specific Observable Evidence */}
              <div className="bg-white/90 rounded-xl p-3 border border-slate-200 mb-3 space-y-1.5 shadow-2xs">
                <span className="text-[11px] font-bold text-slate-900 block mb-1">
                  Observable Evidentiary Points:
                </span>
                <ul className="space-y-1 text-[11.5px] text-slate-700">
                  {result.evidence.map((ev, i) => (
                    <li key={i} className="flex items-start gap-1.5 leading-snug">
                      <span className="text-slate-400 font-black">•</span>
                      <span>{ev}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Limitations / Uncertainty Notice */}
              {result.limitations && (
                <div className="bg-amber-50/70 border border-amber-200/80 rounded-lg p-2.5 mb-3 text-[11px] text-amber-900 leading-snug">
                  <strong className="block mb-0.5">Remaining Uncertainty & Scope:</strong>
                  {result.limitations}
                </div>
              )}

              {/* Recommended Next Step */}
              <div className="rounded-xl bg-[#063E28] text-white p-3.5 shadow-sm">
                <span className="text-[10px] font-black tracking-wider uppercase block mb-1.5 text-emerald-200">
                  Recommended Safe Next Steps:
                </span>
                <p className="text-xs text-white leading-relaxed font-medium">
                  {result.recommended_next_step}
                </p>

                {result.emergency_helpline_needed && (
                  <div className="mt-3 pt-2.5 border-t border-emerald-700/60 flex items-center justify-between">
                    <span className="text-[11px] text-emerald-100">Suspect compromise or extortion?</span>
                    <a
                      href="tel:1991"
                      className="inline-flex items-center gap-1 bg-[#DC2626] hover:bg-red-700 text-white px-2.5 py-1 rounded-lg text-xs font-black shadow-xs no-underline"
                    >
                      <PhoneCall className="w-3 h-3" />
                      <span>Call FIA 1991</span>
                    </a>
                  </div>
                )}
              </div>
            </div>

            {/* Collapsible Source Verification Record */}
            {result.sources_checked && result.sources_checked.length > 0 && (
              <div className="border border-slate-200 rounded-xl bg-[#F8FAFC] overflow-hidden text-left">
                <button
                  type="button"
                  onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                  className="w-full px-3.5 py-2.5 flex items-center justify-between text-xs font-bold text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
                >
                  <span>Authoritative References Checked ({result.sources_checked.length})</span>
                  {showTechnicalDetails ? (
                    <ChevronUp className="w-4 h-4 text-slate-500" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-500" />
                  )}
                </button>

                {showTechnicalDetails && (
                  <div className="p-3 border-t border-slate-200 bg-white space-y-2 text-xs animate-in fade-in">
                    {result.sources_checked.map((src, i) => (
                      <div key={i} className="flex items-center justify-between p-1.5 rounded-lg bg-slate-50 border border-slate-200/60 text-[11px]">
                        <div>
                          <span className="font-semibold text-slate-900 block">{src.name}</span>
                          <span className="text-slate-500 text-[10px] block">{src.url}</span>
                        </div>
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800">
                          {src.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* User Feedback / False-Positive Reporting Trigger */}
            <div className="flex items-center justify-between px-1 text-[11px] text-slate-500">
              <span>Is this assessment inaccurate?</span>
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
                <h4 className="text-sm font-bold text-slate-900">Report Inaccurate Assessment</h4>
                <button
                  type="button"
                  onClick={() => setShowFeedbackModal(false)}
                  className="text-slate-400 hover:text-slate-600"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <p className="text-xs text-slate-600 mb-3 leading-relaxed">
                Cyber Saathi strives to prevent false accusations. If this screenshot is a genuine notice or document, let our team know.
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
                    placeholder="e.g. This is a legitimate notification from my mobile operator confirming my balance..."
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
