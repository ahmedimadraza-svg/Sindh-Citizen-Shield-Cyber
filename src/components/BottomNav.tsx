import React from 'react';
import { ShieldCheck, ScanLine, PhoneCall, Bot } from 'lucide-react';
import { Translations } from '../data/translations';

export type NavTab = 'check-link' | 'analyze-image' | 'fia-1991' | 'chat-counselor';

interface BottomNavProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  t: Translations;
}

export const BottomNav: React.FC<BottomNavProps> = ({ currentTab, onTabChange, t }) => {
  return (
    <nav className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-white/95 backdrop-blur-md border-t border-slate-200/90 py-1.5 px-3 shadow-lg">
      <div className="max-w-md mx-auto grid grid-cols-4 gap-1 text-center">
        {/* Tab 1: Check Link */}
        <button
          type="button"
          onClick={() => onTabChange('check-link')}
          className={`flex flex-col items-center justify-center py-1 rounded-xl transition-all cursor-pointer ${
            currentTab === 'check-link'
              ? 'text-[#063E28] font-extrabold'
              : 'text-slate-500 hover:text-slate-800 font-medium'
          }`}
          aria-label={t.navCheckLink}
        >
          <div
            className={`w-7 h-7 flex items-center justify-center rounded-lg transition-colors ${
              currentTab === 'check-link' ? 'bg-[#E6F4EA] text-[#063E28]' : ''
            }`}
          >
            <ShieldCheck className="w-5 h-5" />
          </div>
          <span className="text-[10px] mt-0.5 tracking-tight">{t.navCheckLink}</span>
        </button>

        {/* Tab 2: Analyze Image */}
        <button
          type="button"
          onClick={() => onTabChange('analyze-image')}
          className={`flex flex-col items-center justify-center py-1 rounded-xl transition-all cursor-pointer ${
            currentTab === 'analyze-image'
              ? 'text-[#063E28] font-extrabold'
              : 'text-slate-500 hover:text-slate-800 font-medium'
          }`}
          aria-label={t.navAnalyzeImage}
        >
          <div
            className={`w-7 h-7 flex items-center justify-center rounded-lg transition-colors ${
              currentTab === 'analyze-image' ? 'bg-[#E6F4EA] text-[#063E28]' : ''
            }`}
          >
            <ScanLine className="w-5 h-5" />
          </div>
          <span className="text-[10px] mt-0.5 tracking-tight">{t.navAnalyzeImage}</span>
        </button>

        {/* Tab 3: FIA 1991 */}
        <button
          type="button"
          onClick={() => onTabChange('fia-1991')}
          className={`flex flex-col items-center justify-center py-1 rounded-xl transition-all cursor-pointer ${
            currentTab === 'fia-1991'
              ? 'text-[#DC2626] font-extrabold'
              : 'text-slate-500 hover:text-slate-800 font-medium'
          }`}
          aria-label={t.navFia1991}
        >
          <div
            className={`w-7 h-7 flex items-center justify-center rounded-lg transition-colors ${
              currentTab === 'fia-1991' ? 'bg-[#FEE2E2] text-[#DC2626]' : ''
            }`}
          >
            <PhoneCall className="w-5 h-5" />
          </div>
          <span className="text-[10px] mt-0.5 tracking-tight">{t.navFia1991}</span>
        </button>

        {/* Tab 4: Cyber Saathi AI Chatbot */}
        <button
          type="button"
          onClick={() => onTabChange('chat-counselor')}
          className={`flex flex-col items-center justify-center py-1 rounded-xl transition-all cursor-pointer ${
            currentTab === 'chat-counselor'
              ? 'text-[#063E28] font-extrabold'
              : 'text-slate-500 hover:text-slate-800 font-medium'
          }`}
          aria-label="Ask Cyber Saathi AI Counselor"
        >
          <div
            className={`w-7 h-7 flex items-center justify-center rounded-lg transition-colors ${
              currentTab === 'chat-counselor' ? 'bg-[#E6F4EA] text-[#063E28]' : ''
            }`}
          >
            <Bot className="w-5 h-5" />
          </div>
          <span className="text-[10px] mt-0.5 tracking-tight">Cyber Saathi AI</span>
        </button>
      </div>
    </nav>
  );
};
