import React from 'react';
import { Shield, PhoneCall } from 'lucide-react';
import { SupportedLanguage } from '../data/translations';
import { CyberSaathiLogo } from './CyberSaathiLogo';

interface HeaderProps {
  currentLang: SupportedLanguage;
  onLanguageChange: (lang: SupportedLanguage) => void;
  onEmergencyClick: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentLang,
  onLanguageChange,
  onEmergencyClick,
}) => {
  return (
    <header className="sticky top-0 z-40 bg-[#FAF8FF]/95 backdrop-blur-md border-b border-slate-200/80 px-4 py-2.5 transition-all">
      <div className="max-w-4xl mx-auto flex items-center justify-between">
        {/* Left: Professional Shield Protection Logo with integrated S emblem */}
        <div className="flex items-center gap-2.5">
          <CyberSaathiLogo size="md" />
          <div className="flex flex-col">
            <h1 className="text-sm sm:text-base font-extrabold text-[#131B2E] tracking-tight leading-tight flex items-center gap-1.5">
              <span>
                {currentLang === 'sd'
                  ? 'سنڌ سائبر ساٿي'
                  : currentLang === 'ur'
                  ? 'سندھ سائبر ساتھی'
                  : 'Sindh Cyber Saathi'}
              </span>
              <span className="text-[10px] font-semibold bg-[#E6F4EA] text-[#063E28] px-1.5 py-0.2 rounded border border-[#CEEAD6]">
                Gov of Sindh
              </span>
            </h1>
            <span className="text-[11px] font-medium text-[#36684F] leading-tight">
              {currentLang === 'sd'
                ? 'سرڪاري شهري سائبر بچاءُ'
                : currentLang === 'ur'
                ? 'سرکاری شہری سائبر تحفظ'
                : 'Civic Cyber Defense • Innovation Challenge'}
            </span>
          </div>
        </div>

        {/* Right: 3-Way Language Toggle & FIA 1991 Emergency */}
        <div className="flex items-center gap-2">
          {/* 3-Language selector toggle button */}
          <div className="inline-flex items-center bg-[#EAEDFF] rounded-full p-0.5 border border-slate-300/80 text-xs font-semibold">
            <button
              onClick={() => onLanguageChange('en')}
              className={`px-2 py-0.5 rounded-full text-[11px] font-bold transition-all cursor-pointer ${
                currentLang === 'en'
                  ? 'bg-white text-[#063E28] shadow-xs font-extrabold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
              aria-label="Switch to English"
            >
              EN
            </button>
            <button
              onClick={() => onLanguageChange('sd')}
              className={`px-2 py-0.5 rounded-full text-[11px] font-bold transition-all cursor-pointer ${
                currentLang === 'sd'
                  ? 'bg-white text-[#063E28] shadow-xs font-extrabold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
              aria-label="سنڌي ۾ تبديل ڪريو"
            >
              سنڌي
            </button>
            <button
              onClick={() => onLanguageChange('ur')}
              className={`px-2 py-0.5 rounded-full text-[11px] font-bold transition-all cursor-pointer ${
                currentLang === 'ur'
                  ? 'bg-white text-[#063E28] shadow-xs font-extrabold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
              aria-label="اردو میں تبدیل کریں"
            >
              اردو
            </button>
          </div>

          {/* Red Emergency FIA 1991 Pill Button */}
          <button
            onClick={onEmergencyClick}
            className="flex items-center gap-1.5 bg-[#DC2626] hover:bg-[#B91C1C] text-white text-xs font-bold px-3 py-1.5 rounded-full shadow-sm transition-all transform active:scale-95 cursor-pointer"
            aria-label="Call FIA Helpline 1991"
          >
            <PhoneCall className="w-3.5 h-3.5 fill-current" />
            <span className="tracking-wide">FIA 1991</span>
          </button>

          {/* Secondary Badge icon */}
          <div className="hidden sm:flex w-8 h-8 rounded-full bg-[#EAEDFF] text-[#36684F] items-center justify-center border border-slate-200 shrink-0">
            <Shield className="w-4 h-4 fill-current opacity-80" />
          </div>
        </div>
      </div>
    </header>
  );
};
