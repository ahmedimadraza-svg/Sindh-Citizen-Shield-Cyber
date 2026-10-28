import React, { useState } from 'react';
import { Gift, Wallet, VideoOff, Zap, ChevronRight, AlertCircle, MapPin, Shield } from 'lucide-react';
import { THREAT_FEED_ITEMS, ThreatFeedItem } from '../data/threatFeedData';
import { Translations } from '../data/translations';

interface ThreatFeedProps {
  t: Translations;
  isRTL: boolean;
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({ t, isRTL }) => {
  const [selectedItem, setSelectedItem] = useState<ThreatFeedItem | null>(null);

  const getIcon = (type: string) => {
    switch (type) {
      case 'welfare':
        return (
          <div className="w-10 h-10 rounded-xl bg-[#FEE2E2] text-[#DC2626] flex items-center justify-center shrink-0 border border-[#FECACA]">
            <Gift className="w-5 h-5 stroke-[2.2]" />
          </div>
        );
      case 'wallet':
        return (
          <div className="w-10 h-10 rounded-xl bg-[#FEF3C7] text-[#D97706] flex items-center justify-center shrink-0 border border-[#FDE68A]">
            <Wallet className="w-5 h-5 stroke-[2.2]" />
          </div>
        );
      case 'blackmail':
        return (
          <div className="w-10 h-10 rounded-xl bg-[#D1FAE5] text-[#059669] flex items-center justify-center shrink-0 border border-[#A7F3D0]">
            <VideoOff className="w-5 h-5 stroke-[2.2]" />
          </div>
        );
      default:
        return (
          <div className="w-10 h-10 rounded-xl bg-[#E0E7FF] text-[#4F46E5] flex items-center justify-center shrink-0 border border-[#C7D2FE]">
            <Zap className="w-5 h-5 stroke-[2.2]" />
          </div>
        );
    }
  };

  const getBadgeStyle = (color: string) => {
    switch (color) {
      case 'red':
        return 'bg-[#FEE2E2] text-[#B91C1C] border border-[#FECACA]';
      case 'amber':
        return 'bg-[#FEF3C7] text-[#92400E] border border-[#FDE68A]';
      case 'emerald':
        return 'bg-[#D1FAE5] text-[#065F46] border border-[#A7F3D0]';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <section id="threat-feed" className="px-4 py-2 max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-2.5">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-[#063E28] text-white flex items-center justify-center text-xs font-bold">
            !
          </div>
          <h3 className="text-base font-bold text-[#131B2E]">
            {t.threatFeedTitle}
          </h3>
        </div>
        <span className="text-[11px] font-bold text-[#006C49] bg-[#E6F4EA] px-2 py-0.5 rounded-full border border-[#CEEAD6]">
          {t.threatFeedBadge}
        </span>
      </div>

      {/* Cards List */}
      <div className="space-y-2.5">
        {THREAT_FEED_ITEMS.map((item) => (
          <div
            key={item.id}
            onClick={() => setSelectedItem(item)}
            className="card-tactile rounded-2xl p-3.5 bg-white shadow-xs hover:border-slate-300 transition-all cursor-pointer text-left"
          >
            {/* Top Row: Icon + Title + Badge */}
            <div className="flex items-start gap-2.5 mb-2">
              {getIcon(item.iconType)}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-1 mb-0.5">
                  <h4 className="text-[13px] font-bold text-[#131B2E] truncate">
                    {item.title}
                  </h4>
                  <span
                    className={`text-[9px] font-black px-2 py-0.5 rounded-full uppercase tracking-wider shrink-0 ${getBadgeStyle(
                      item.badgeColor
                    )}`}
                  >
                    {item.badge}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 truncate">
                  {item.subtitle}
                </p>
              </div>
            </div>

            {/* Quote container */}
            <div className="bg-[#F8FAFC] border border-slate-200/90 rounded-xl p-2.5 font-mono text-[11px] text-slate-700 leading-snug">
              {item.quote}
            </div>

            {/* Quick Action Footer */}
            <div className="flex items-center justify-between mt-2 pt-1 text-[10px] text-slate-500">
              <span className="flex items-center gap-1 font-medium">
                <MapPin className="w-3 h-3 text-slate-400" />
                {item.reportedLocation}
              </span>
              <span className="text-[#063E28] font-bold flex items-center gap-0.5">
                Civic Advisory
                <ChevronRight className="w-3 h-3" />
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Modal with Details when clicked */}
      {selectedItem && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-sm w-full p-5 shadow-2xl border border-slate-200 text-left animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between mb-3">
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${getBadgeStyle(
                  selectedItem.badgeColor
                )}`}
              >
                {selectedItem.badge}
              </span>
              <button
                onClick={() => setSelectedItem(null)}
                className="w-7 h-7 rounded-full bg-slate-100 hover:bg-slate-200 flex items-center justify-center text-slate-600 font-bold"
              >
                ×
              </button>
            </div>

            <h3 className="text-base font-extrabold text-[#131B2E] mb-1">
              {selectedItem.title}
            </h3>

            <p className="text-xs text-slate-600 mb-3 font-mono bg-slate-100 p-2.5 rounded-lg border border-slate-200">
              {selectedItem.quote}
            </p>

            <div className="rounded-xl bg-[#F0FDF4] border border-emerald-200 p-3 mb-4">
              <span className="text-[11px] font-bold text-emerald-900 flex items-center gap-1 mb-1">
                <Shield className="w-3.5 h-3.5 text-emerald-700" />
                Sindh Police & FIA Advisory
              </span>
              <p className="text-xs text-emerald-950 leading-relaxed">
                {selectedItem.advisory}
              </p>
            </div>

            <button
              onClick={() => setSelectedItem(null)}
              className="w-full py-2.5 bg-[#063E28] hover:bg-[#084c32] text-white text-xs font-bold rounded-xl"
            >
              Acknowledged
            </button>
          </div>
        </div>
      )}
    </section>
  );
};
