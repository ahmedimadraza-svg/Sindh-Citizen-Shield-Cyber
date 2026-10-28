import React from 'react';
import { Link2, ScanLine, ArrowRight, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { Translations } from '../data/translations';

export type ActiveToolView = 'both' | 'link' | 'screenshot';

interface ProminentActionSelectorProps {
  t: Translations;
  isRTL: boolean;
  activeView: ActiveToolView;
  onSelectView: (view: ActiveToolView) => void;
}

export const ProminentActionSelector: React.FC<ProminentActionSelectorProps> = ({
  t,
  isRTL,
  activeView,
  onSelectView,
}) => {
  const handleSelect = (view: ActiveToolView, elementId?: string) => {
    onSelectView(view);
    if (elementId) {
      setTimeout(() => {
        const el = document.getElementById(elementId);
        el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 50);
    }
  };

  return (
    <section className="px-4 py-2 max-w-3xl mx-auto">
      {/* View Switcher Pills */}
      <div className="flex items-center justify-center gap-1.5 p-1 bg-slate-200/70 rounded-2xl mb-3.5 max-w-md mx-auto">
        <button
          type="button"
          onClick={() => handleSelect('link', 'link-inspector')}
          className={`flex-1 py-2 px-3 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
            activeView === 'link'
              ? 'bg-[#063E28] text-white shadow-sm'
              : 'text-slate-700 hover:text-slate-900 hover:bg-white/60'
          }`}
          aria-label={t.actionCheckLink}
        >
          <Link2 className="w-3.5 h-3.5" />
          <span>{t.actionCheckLink}</span>
        </button>

        <button
          type="button"
          onClick={() => handleSelect('screenshot', 'screenshot-analyzer')}
          className={`flex-1 py-2 px-3 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
            activeView === 'screenshot'
              ? 'bg-[#063E28] text-white shadow-sm'
              : 'text-slate-700 hover:text-slate-900 hover:bg-white/60'
          }`}
          aria-label={t.actionCheckScreenshot}
        >
          <ScanLine className="w-3.5 h-3.5" />
          <span>{t.actionCheckScreenshot}</span>
        </button>

        <button
          type="button"
          onClick={() => handleSelect('both')}
          className={`py-2 px-3 rounded-xl text-xs font-bold transition-all cursor-pointer flex items-center justify-center gap-1 ${
            activeView === 'both'
              ? 'bg-white text-[#063E28] shadow-sm font-extrabold'
              : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
          }`}
          aria-label={t.activeTabBoth}
        >
          <span>{t.activeTabBoth}</span>
        </button>
      </div>

      {/* Two Prominent Action Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 mb-2">
        {/* Action 1: Check a Link */}
        <div
          onClick={() => handleSelect('link', 'link-inspector')}
          className={`group rounded-2xl p-4.5 transition-all cursor-pointer border-2 text-left relative overflow-hidden flex flex-col justify-between ${
            activeView === 'link'
              ? 'bg-gradient-to-br from-[#F0FDF4] to-[#ECFDF5] border-[#063E28] shadow-md ring-2 ring-[#063E28]/10'
              : 'bg-white border-slate-200/90 hover:border-emerald-600/60 hover:shadow-sm'
          }`}
        >
          <div className="flex items-start justify-between gap-3 mb-3">
            <div className="w-12 h-12 rounded-2xl bg-[#063E28] text-white flex items-center justify-center shrink-0 shadow-sm group-hover:scale-105 transition-transform">
              <Link2 className="w-6 h-6 stroke-[2.2]" />
            </div>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-emerald-100 text-[#063E28] border border-emerald-200">
              Safe Browsing
            </span>
          </div>

          <div>
            <h3 className="text-base font-extrabold text-[#131B2E] tracking-tight mb-1 flex items-center gap-1.5">
              <span>{t.actionCheckLink}</span>
              {activeView === 'link' && (
                <CheckCircle2 className="w-4 h-4 text-[#063E28] fill-emerald-100" />
              )}
            </h3>
            <p className="text-xs text-slate-600 leading-relaxed mb-4">
              {t.actionCheckLinkDesc}
            </p>
          </div>

          <div className="flex items-center justify-between text-xs font-bold text-[#063E28] pt-2 border-t border-slate-100">
            <span>Scan URL for Threats</span>
            <ArrowRight className={`w-4 h-4 transition-transform group-hover:translate-x-1 ${isRTL ? 'rotate-180' : ''}`} />
          </div>
        </div>

        {/* Action 2: Check a Screenshot */}
        <div
          onClick={() => handleSelect('screenshot', 'screenshot-analyzer')}
          className={`group rounded-2xl p-4.5 transition-all cursor-pointer border-2 text-left relative overflow-hidden flex flex-col justify-between ${
            activeView === 'screenshot'
              ? 'bg-gradient-to-br from-[#F0FDF4] to-[#ECFDF5] border-[#063E28] shadow-md ring-2 ring-[#063E28]/10'
              : 'bg-white border-slate-200/90 hover:border-emerald-600/60 hover:shadow-sm'
          }`}
        >
          <div className="flex items-start justify-between gap-3 mb-3">
            <div className="w-12 h-12 rounded-2xl bg-[#063E28] text-white flex items-center justify-center shrink-0 shadow-sm group-hover:scale-105 transition-transform">
              <ScanLine className="w-6 h-6 stroke-[2.2]" />
            </div>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-emerald-100 text-[#063E28] border border-emerald-200">
              Forensic Vision
            </span>
          </div>

          <div>
            <h3 className="text-base font-extrabold text-[#131B2E] tracking-tight mb-1 flex items-center gap-1.5">
              <span>{t.actionCheckScreenshot}</span>
              {activeView === 'screenshot' && (
                <CheckCircle2 className="w-4 h-4 text-[#063E28] fill-emerald-100" />
              )}
            </h3>
            <p className="text-xs text-slate-600 leading-relaxed mb-4">
              {t.actionCheckScreenshotDesc}
            </p>
          </div>

          <div className="flex items-center justify-between text-xs font-bold text-[#063E28] pt-2 border-t border-slate-100">
            <span>Examine Image Evidence</span>
            <ArrowRight className={`w-4 h-4 transition-transform group-hover:translate-x-1 ${isRTL ? 'rotate-180' : ''}`} />
          </div>
        </div>
      </div>
    </section>
  );
};
