import React from 'react';
import { PhoneCall, FileText, ExternalLink, ShieldAlert, CheckCircle2, X } from 'lucide-react';
import { Translations } from '../data/translations';

interface EmergencyModalProps {
  isOpen: boolean;
  onClose: () => void;
  t: Translations;
  isRTL: boolean;
}

export const EmergencyModal: React.FC<EmergencyModalProps> = ({
  isOpen,
  onClose,
  t,
  isRTL,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white rounded-3xl max-w-md w-full p-5 sm:p-6 shadow-2xl border border-red-200 text-left relative overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
        {/* Top Crimson Accent Header */}
        <div className="flex items-start justify-between gap-3 mb-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-2xl bg-[#DC2626] text-white flex items-center justify-center shrink-0 shadow-md">
              <PhoneCall className="w-6 h-6 stroke-[2.2]" />
            </div>
            <div>
              <span className="text-[10px] font-black tracking-wider text-red-700 uppercase bg-red-100 px-2 py-0.5 rounded-full inline-block mb-1">
                24/7 Rapid Response
              </span>
              <h3 className="text-base font-extrabold text-[#111827] leading-tight">
                {t.emergencyModalTitle}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-full bg-slate-100 hover:bg-slate-200 flex items-center justify-center text-slate-600 transition-colors shrink-0 cursor-pointer"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-600 mb-4 leading-relaxed">
          {t.emergencyModalDesc}
        </p>

        {/* 3 Urgent Steps */}
        <div className="space-y-3 mb-5">
          {/* Step 1 */}
          <div className="rounded-xl bg-[#FEF2F2] border border-red-200 p-3.5 flex items-start gap-3">
            <div className="w-6 h-6 rounded-full bg-[#B91C1C] text-white flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
              1
            </div>
            <div>
              <h4 className="text-xs font-bold text-red-900 mb-0.5">
                Golden Hour Fund Freeze
              </h4>
              <p className="text-[11px] text-red-950/90 leading-snug">
                {t.emergencyStep1}
              </p>
            </div>
          </div>

          {/* Step 2 */}
          <div className="rounded-xl bg-slate-50 border border-slate-200 p-3.5 flex items-start gap-3">
            <div className="w-6 h-6 rounded-full bg-[#063E28] text-white flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
              2
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-900 mb-0.5">
                Inter-Bank 1Link Reversal
              </h4>
              <p className="text-[11px] text-slate-700 leading-snug">
                {t.emergencyStep2}
              </p>
            </div>
          </div>

          {/* Step 3 */}
          <div className="rounded-xl bg-slate-50 border border-slate-200 p-3.5 flex items-start gap-3">
            <div className="w-6 h-6 rounded-full bg-[#063E28] text-white flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
              3
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-900 mb-0.5">
                Preserve Digital Evidence
              </h4>
              <p className="text-[11px] text-slate-700 leading-snug">
                {t.emergencyStep3}
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons & Verified Links */}
        <div className="space-y-2">
          {/* Direct Phone Call Link */}
          <a
            href="tel:1991"
            className="btn-tactile-emergency w-full py-3.5 px-4 rounded-xl font-extrabold text-sm flex items-center justify-center gap-2 cursor-pointer no-underline text-center text-white"
          >
            <PhoneCall className="w-4 h-4 fill-current" />
            <span>{t.dialNowBtn}</span>
          </a>

          {/* Official FIA Online Complaint Portal Link */}
          <a
            href="https://complaint.fia.gov.pk"
            target="_blank"
            rel="noopener noreferrer"
            className="w-full py-2.5 px-4 rounded-xl font-bold text-xs flex items-center justify-center gap-1.5 text-[#063E28] bg-[#E6F4EA] hover:bg-[#CEEAD6] transition-colors border border-[#A7F3D0] no-underline"
          >
            <FileText className="w-3.5 h-3.5 text-[#063E28]" />
            <span>Launch Official FIA Online Portal (complaint.fia.gov.pk)</span>
            <ExternalLink className="w-3 h-3 text-[#063E28]" />
          </a>

          {/* PTA Illegal Content / SIM Complaint Portal Link */}
          <a
            href="https://complaint.pta.gov.pk"
            target="_blank"
            rel="noopener noreferrer"
            className="w-full py-2 px-4 rounded-xl font-semibold text-xs flex items-center justify-center gap-1.5 text-slate-700 bg-slate-100 hover:bg-slate-200 transition-colors border border-slate-200 no-underline"
          >
            <span>Block Fraudulent SIM / URL via PTA Portal (complaint.pta.gov.pk)</span>
            <ExternalLink className="w-3 h-3 text-slate-500" />
          </a>

          <button
            type="button"
            onClick={onClose}
            className="w-full py-2 text-xs font-semibold text-slate-500 hover:text-slate-800 cursor-pointer"
          >
            {t.closeBtn}
          </button>
        </div>
      </div>
    </div>
  );
};
