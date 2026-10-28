import React from 'react';
import { ShieldAlert } from 'lucide-react';
import { Translations } from '../data/translations';

interface HeroBannerProps {
  t: Translations;
  isRTL: boolean;
}

export const HeroBanner: React.FC<HeroBannerProps> = ({ t, isRTL }) => {
  return (
    <section className="px-4 pt-3 pb-2 max-w-3xl mx-auto">
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-b from-[#063E28] via-[#043320] to-[#022416] text-white p-5 shadow-md border border-[#0A5739]/50">
        {/* Subtle decorative grid/glow behind */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-[#10B981]/10 rounded-full blur-2xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-40 h-40 bg-[#000000]/30 rounded-full blur-xl pointer-events-none" />

        {/* Top Badges row */}
        <div className="flex items-center gap-2 mb-3.5 flex-wrap">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#0E5136]/90 border border-[#166E4B]/80 text-[11px] font-bold text-emerald-200 tracking-wider uppercase">
            <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
            <span>{t.heroTag}</span>
          </div>
          <span className="text-[12px] text-emerald-200/80 font-medium flex items-center gap-1">
            <ShieldAlert className="w-3.5 h-3.5 text-emerald-300" />
            {t.heroDefenseLink}
          </span>
        </div>

        {/* Main Headline */}
        <h2 className={`text-[23px] sm:text-[25px] font-extrabold leading-[1.25] text-white tracking-tight mb-2.5 ${isRTL ? 'text-right' : 'text-left'}`}>
          {t.heroTitle}
        </h2>

        {/* Subtitle */}
        <p className={`text-[13px] leading-relaxed text-emerald-100/85 font-normal ${isRTL ? 'text-right' : 'text-left'}`}>
          {t.heroSubtitle}
        </p>
      </div>
    </section>
  );
};
