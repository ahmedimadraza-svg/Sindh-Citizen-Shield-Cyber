import React from 'react';
import { Landmark, Ban } from 'lucide-react';
import { Translations } from '../data/translations';

interface CyberHygieneRulesProps {
  t: Translations;
  isRTL: boolean;
}

export const CyberHygieneRules: React.FC<CyberHygieneRulesProps> = ({ t, isRTL }) => {
  return (
    <section className="px-4 py-3 max-w-3xl mx-auto mb-16">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <div className="w-5 h-5 rounded-md bg-[#0F172A] text-white flex items-center justify-center text-xs font-black">
          3
        </div>
        <h3 className="text-sm font-bold text-[#131B2E]">
          {t.hygieneRulesTitle}
        </h3>
      </div>

      {/* 3 Column Cards Grid */}
      <div className="grid grid-cols-3 gap-2">
        {/* Card 1: Never Share OTP */}
        <div className="card-tactile rounded-2xl p-3 bg-white text-center flex flex-col items-center justify-start border border-slate-200/90 shadow-xs">
          <div className="w-9 h-9 rounded-xl bg-[#FFE4E6] text-[#E11D48] flex items-center justify-center font-bold text-xs mb-2 border border-[#FECDD3]">
            <span className="font-mono font-black text-[11px] tracking-tighter">123</span>
          </div>
          <h4 className="text-[12px] font-bold text-[#131B2E] leading-tight mb-1">
            {t.hygieneRule1Title}
          </h4>
          <p className="text-[10px] text-slate-500 leading-tight">
            {t.hygieneRule1Desc}
          </p>
        </div>

        {/* Card 2: Verify .gov.pk */}
        <div className="card-tactile rounded-2xl p-3 bg-white text-center flex flex-col items-center justify-start border border-slate-200/90 shadow-xs">
          <div className="w-9 h-9 rounded-xl bg-[#DBEAFE] text-[#1D4ED8] flex items-center justify-center font-bold text-xs mb-2 border border-[#BFDBFE]">
            <Landmark className="w-4 h-4 stroke-[2.2]" />
          </div>
          <h4 className="text-[12px] font-bold text-[#131B2E] leading-tight mb-1">
            {t.hygieneRule2Title}
          </h4>
          <p className="text-[10px] text-slate-500 leading-tight">
            {t.hygieneRule2Desc}
          </p>
        </div>

        {/* Card 3: No Advance Fees */}
        <div className="card-tactile rounded-2xl p-3 bg-white text-center flex flex-col items-center justify-start border border-slate-200/90 shadow-xs">
          <div className="w-9 h-9 rounded-xl bg-[#DCFCE7] text-[#16A34A] flex items-center justify-center font-bold text-xs mb-2 border border-[#BBF7D0]">
            <Ban className="w-4 h-4 stroke-[2.2]" />
          </div>
          <h4 className="text-[12px] font-bold text-[#131B2E] leading-tight mb-1">
            {t.hygieneRule3Title}
          </h4>
          <p className="text-[10px] text-slate-500 leading-tight">
            {t.hygieneRule3Desc}
          </p>
        </div>
      </div>
    </section>
  );
};
