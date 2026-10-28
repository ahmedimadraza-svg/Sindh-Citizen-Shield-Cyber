import React from 'react';
import { PhoneCall } from 'lucide-react';
import { Translations } from '../data/translations';

interface HelplineBannerProps {
  t: Translations;
  onCallHelpline: () => void;
  isRTL: boolean;
}

export const HelplineBanner: React.FC<HelplineBannerProps> = ({
  t,
  onCallHelpline,
  isRTL,
}) => {
  return (
    <section id="fia-1991" className="px-4 py-2 max-w-3xl mx-auto">
      <div className="rounded-2xl bg-[#8F1414] text-white p-4 sm:p-5 shadow-md border border-red-700/60 relative overflow-hidden">
        {/* Glow backdrop */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-red-400/10 rounded-full blur-2xl pointer-events-none" />

        <div className="flex items-center justify-between gap-3">
          {/* Left Text & Details */}
          <div className="flex-1 text-left">
            <div className="flex items-center gap-1.5 mb-1 text-rose-200 text-[11px] font-bold tracking-wider uppercase">
              <div className="w-5 h-5 rounded-full bg-red-900/60 border border-red-600/40 flex items-center justify-center shrink-0">
                <PhoneCall className="w-3 h-3 text-rose-300" />
              </div>
              <span>{t.emergencyHelplineLabel}</span>
            </div>

            <h3 className="text-[16px] font-extrabold text-white leading-tight mb-1">
              {t.emergencyHelplineTitle}
            </h3>

            <p className="text-[12px] text-rose-100/85 leading-snug">
              {t.emergencyHelplineSubtitle}
            </p>
          </div>

          {/* Right: Big White 1991 Dial Pill */}
          <button
            type="button"
            onClick={onCallHelpline}
            className="shrink-0 bg-white hover:bg-rose-50 text-[#8F1414] font-black text-xl px-4 py-3 rounded-2xl shadow-md border border-white/80 transition-all transform active:scale-95 cursor-pointer flex items-center justify-center min-w-[76px] h-[52px]"
            aria-label="Direct dial FIA Helpline 1991"
          >
            <span className="tracking-tight">{t.emergencyDialCode}</span>
          </button>
        </div>
      </div>
    </section>
  );
};
