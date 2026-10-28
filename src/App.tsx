/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { HeroBanner } from './components/HeroBanner';
import { ProminentActionSelector, ActiveToolView } from './components/ProminentActionSelector';
import { LinkInspector } from './components/LinkInspector';
import { ScreenshotAnalyzer } from './components/ScreenshotAnalyzer';
import { HelplineBanner } from './components/HelplineBanner';
import { ThreatFeed } from './components/ThreatFeed';
import { CyberHygieneRules } from './components/CyberHygieneRules';
import { BottomNav, NavTab } from './components/BottomNav';
import { EmergencyModal } from './components/EmergencyModal';
import { CyberSaathiChatbot } from './components/CyberSaathiChatbot';
import { CyberSaathiLogo } from './components/CyberSaathiLogo';
import { SupportedLanguage, translations } from './data/translations';

export default function App() {
  const [currentLang, setCurrentLang] = useState<SupportedLanguage>('en');
  const [activeTab, setActiveTab] = useState<NavTab>('check-link');
  const [activeToolView, setActiveToolView] = useState<ActiveToolView>('both');
  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState<boolean>(false);
  const [isChatbotOpen, setIsChatbotOpen] = useState<boolean>(false);

  const t = translations[currentLang];
  const isRTL = currentLang === 'sd' || currentLang === 'ur';

  useEffect(() => {
    document.documentElement.dir = isRTL ? 'rtl' : 'ltr';
    document.documentElement.lang = currentLang;
  }, [currentLang, isRTL]);

  const handleTabChange = (tab: NavTab) => {
    setActiveTab(tab);
    if (tab === 'check-link') {
      setActiveToolView('link');
      const el = document.getElementById('link-inspector');
      el?.scrollIntoView({ behavior: 'smooth' });
    } else if (tab === 'analyze-image') {
      setActiveToolView('screenshot');
      const el = document.getElementById('screenshot-analyzer');
      el?.scrollIntoView({ behavior: 'smooth' });
    } else if (tab === 'fia-1991') {
      setIsEmergencyModalOpen(true);
    } else if (tab === 'chat-counselor') {
      setIsChatbotOpen(true);
    }
  };

  return (
    <div className={`min-h-screen bg-[#FAF8FF] text-[#131B2E] pb-16 ${isRTL ? 'font-arabic' : 'font-sans'}`}>
      {/* Top Header with Cyber Saathi Shield Logo */}
      <Header
        currentLang={currentLang}
        onLanguageChange={setCurrentLang}
        onEmergencyClick={() => setIsEmergencyModalOpen(true)}
      />

      {/* Main Content Flow */}
      <main className="space-y-1">
        {/* Hero Banner */}
        <HeroBanner t={t} isRTL={isRTL} />

        {/* Two Prominent Actions Selector: Check a Link & Check a Screenshot */}
        <ProminentActionSelector
          t={t}
          isRTL={isRTL}
          activeView={activeToolView}
          onSelectView={setActiveToolView}
        />

        {/* User-driven Instant Link Inspector */}
        {(activeToolView === 'both' || activeToolView === 'link') && (
          <div className="transition-all animate-in fade-in duration-200">
            <LinkInspector t={t} isRTL={isRTL} />
          </div>
        )}

        {/* User-driven Screenshot & SMS Photo Analyzer */}
        {(activeToolView === 'both' || activeToolView === 'screenshot') && (
          <div className="transition-all animate-in fade-in duration-200">
            <ScreenshotAnalyzer t={t} isRTL={isRTL} />
          </div>
        )}

        {/* 24/7 Federal Emergency Helpline Banner */}
        <HelplineBanner
          t={t}
          onCallHelpline={() => setIsEmergencyModalOpen(true)}
          isRTL={isRTL}
        />

        {/* Common Digital Scams in Sindh (Threat Feed) */}
        <ThreatFeed t={t} isRTL={isRTL} />

        {/* Essential Citizen Cyber Hygiene Rules */}
        <CyberHygieneRules t={t} isRTL={isRTL} />
      </main>

      {/* Floating Cyber Saathi AI Chatbot Trigger on desktop (hidden on viewports where bottom nav has Cyber Saathi AI tab) */}
      <button
        onClick={() => setIsChatbotOpen(true)}
        className="hidden md:flex fixed bottom-6 right-6 z-40 bg-[#063E28] hover:bg-[#084c32] text-white px-3.5 py-2.5 rounded-full shadow-lg border border-[#0A5739] items-center gap-2 cursor-pointer transition-transform transform active:scale-95"
        aria-label="Open Cyber Saathi AI Counselor"
      >
        <CyberSaathiLogo size="sm" variant="shield-ai" />
        <span className="text-xs font-extrabold tracking-tight">Cyber Saathi AI</span>
      </button>

      {/* Persistent Bottom Navigation */}
      <BottomNav
        currentTab={activeTab}
        onTabChange={handleTabChange}
        t={t}
      />

      {/* Emergency Modal for FIA 1991 & Golden Hour Fund Freeze */}
      <EmergencyModal
        isOpen={isEmergencyModalOpen}
        onClose={() => setIsEmergencyModalOpen(false)}
        t={t}
        isRTL={isRTL}
      />

      {/* Interactive Cyber Saathi AI Counselor Chatbot Modal */}
      <CyberSaathiChatbot
        isOpen={isChatbotOpen}
        onClose={() => setIsChatbotOpen(false)}
        currentLang={currentLang}
      />
    </div>
  );
}
