import React, { useState, useRef, useEffect } from 'react';
import { Send, X, ExternalLink, PhoneCall, Bot, User } from 'lucide-react';
import { CyberSaathiLogo } from './CyberSaathiLogo';
import { SupportedLanguage } from '../data/translations';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  time?: string;
}

interface CyberSaathiChatbotProps {
  isOpen: boolean;
  onClose: () => void;
  currentLang: SupportedLanguage;
}

export const CyberSaathiChatbot: React.FC<CyberSaathiChatbotProps> = ({
  isOpen,
  onClose,
  currentLang,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        currentLang === 'sd'
          ? 'سلام! آئون سنڌ سائبر ساٿي (Sindh Cyber Saathi) آهيان، اوهان جو مهربان سائبر تحفظ ساٿي. ڪو به شڪي ميسيج، لنڪ، اسڪرين شاٽ يا ڪال هتي شيئر ڪريو، آئون اوهان کي ٻڌائيندس ته اهو فراڊ آهي، شڪي آهي يا محفوظ. پريشان نه ٿيو، پڇڻ هميشه سٺو هوندو آهي!'
          : currentLang === 'ur'
          ? 'السلام علیکم! میں ہوں سندھ سائبر ساتھی (Sindh Cyber Saathi)، آپ کا بااعتماد اور ہمدرد سائبر سیفٹی ساتھی۔ کوئی بھی میسج، لنک، اسکرین شاٹ، یا کال کی تفصیل یہاں شیئر کریں، میں آپ کو بتاؤں گا کہ یہ دھوکہ ہے، مشکوک ہے یا محفوظ۔ کسی بھی شک کی صورت میں پہلے پوچھنا ہی سب سے دانشمندانہ قدم ہے۔'
          : 'Assalam-o-Alaikum! I am Sindh Cyber Saathi, your friendly cyber-safety companion. Paste any suspicious link, message, screenshot details, or phone offer here. I will tell you if it is safe, suspicious, or a scam. Never hesitate to ask — checking first is always the smart choice!',
      time: 'Just now',
    },
  ]);
  const [inputValue, setInputValue] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputValue).trim();
    if (!text || isLoading) return;

    const userMsg: Message = {
      role: 'user',
      content: text,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInputValue('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/chat-counselor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMsg],
          language: currentLang,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: data.reply,
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          },
        ]);
      } else {
        throw new Error('Non-ok response');
      }
    } catch {
      // Local knowledge fallback adhering to Master Prompt format
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content:
            currentLang === 'sd'
              ? `**Verdict:** 🟡 **شڪي (SUSPICIOUS) — احتياط ڪريو**

**مان ڇو ائين چوان ٿو:**
• اوهان جو ميسيج يا لنڪ مالي يا ذاتي معلومات حاصل ڪرڻ جي ڪوشش ٿي سگهي ٿي.
• ڪو به سرڪاري ادارو يا بينڪ ڪڏهن به ايس ايم ايس يا فون تي پن (PIN) يا او ٽي پي نٿو گهري.

**هاڻي ڇا ڪجي:**
• پنهنجي بينڪ يا جاز ڪيش/ايزي پيسا جي اصل ايپ کولي پنهنجو بيلنس پاڻ چڪاسيو.
• جيڪڏهن ڪو نقصان ٿيو آهي ته ترت ايف آءِ اي هيلپ لائن 1991 تي ڪال ڪريو.

**ڇا نه ڪجي:**
• ڪنهن به اڻڄاتل لنڪ کي نه کوليو، نه ئي ڪنهن کي پن (PIN) يا OTP ٻڌايو.

پهرين چڪاس ڪري اوهان بلڪل صحيح قدم کنيو.`
              : currentLang === 'ur'
              ? `**Verdict:** 🟡 **مشکوک (SUSPICIOUS) — ہوشیار رہیں**

**میری رائے کی وجہ:**
• یہ میسج یا لنک آپ کے ذاتی یا مالی کوائف حاصل کرنے کے لیے ہو سکتا ہے۔
• کوئی بھی بینک، جاز کیش یا ادارہ آپ سے میسج پر پن کوڈ یا OTP نہیں مانگتا۔

**اب کیا کریں:**
• متعلقہ بینک یا والٹ کی آفیشل ایپ خود کھول کر اپنا بیلنس چیک کریں۔
• اگر کوئی رقم کٹ گئی ہے تو فوراً ایف آئی اے ہیلپ لائن 1991 پر کال کریں۔

**کیا نہ کریں:**
• کسی نامعلوم لنک پر کلک نہ کریں، اور کسی کو بھی اپنا پاس ورڈ، پن یا OTP نہ بتائیں۔

پہلے تصدیق کر کے آپ نے بالکل درست فیصلہ کیا۔`
              : `**Verdict:** 🟡 **SUSPICIOUS — BE CAREFUL**

**Why I think so:**
• Unsolicited messages, unknown links, or payment claims must be verified before acting.
• No legitimate bank or wallet will ever ask for your OTP, PIN, or password.

**What to do now:**
• Check your real balance directly inside your official banking or wallet app.
• If money was unauthorizedly deducted, call the FIA Cybercrime Helpline immediately at 1991.

**What NOT to do:**
• Do not open unfamiliar links, do not install APK files, and never share any verification code.

You did the right thing by checking first.`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const quickPrompts = [
    {
      label: currentLang === 'sd' ? 'شڪي يا اڻپوري لنڪ' : currentLang === 'ur' ? 'مشکوک یا ادھورا لنک' : 'Suspicious / Incomplete Link',
      prompt: 'Someone sent me an incomplete link: "https://jazzcash-bonus-claim.xy..." Is this safe to open?',
    },
    {
      label: currentLang === 'sd' ? 'پئسن جي منتقلي جو اسڪرين شاٽ' : currentLang === 'ur' ? 'پیسوں کے ٹرانسفر کا اسکرین شاٹ' : 'Payment Screenshot Received',
      prompt: 'A buyer sent me an Easypaisa payment screenshot, but money did not arrive in my account. Is this real?',
    },
    {
      label: currentLang === 'sd' ? '8171 / BISP امدادي ميسيج' : currentLang === 'ur' ? '8171 / BISP امدادی میسج' : '8171 BISP Cash Message',
      prompt: 'I received an SMS from an 11-digit mobile number claiming Rs. 25,000 BISP Ehsaas grant. Is this genuine?',
    },
    {
      label: currentLang === 'sd' ? 'ڪنهن OTP يا PIN گهريو آهي' : currentLang === 'ur' ? 'کسی نے OTP یا PIN مانگا ہے' : 'Someone Asking for OTP/PIN',
      prompt: 'Someone called pretending to be a bank officer asking for the 6-digit SMS code I just received.',
    },
    {
      label: currentLang === 'sd' ? 'مدد! مون اڳ ۾ ئي پئسا موڪليا آهن' : currentLang === 'ur' ? 'مدد! مجھ سے رقم چوری ہو گئی ہے' : 'Help! I already sent money',
      prompt: 'I accidentally sent money to a scammer and entered my PIN. What immediate steps should I take right now?',
    },
  ];

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4">
      <div className="bg-white rounded-3xl max-w-md w-full h-[620px] max-h-[92vh] flex flex-col shadow-2xl border border-slate-200 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header with Redesigned S Shield Logo */}
        <div className="bg-[#063E28] text-white p-3.5 flex items-center justify-between shadow-xs">
          <div className="flex items-center gap-2.5">
            <CyberSaathiLogo size="sm" variant="shield-ai" />
            <div>
              <div className="flex items-center gap-1.5">
                <h3 className="text-sm font-extrabold tracking-tight">Sindh Cyber Saathi</h3>
                <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
              </div>
              <p className="text-[10.5px] text-emerald-200/90 font-medium">
                {currentLang === 'sd' ? 'اوهان جو بااعتماد ڊجيٽل حفاظت ساٿي' : currentLang === 'ur' ? 'آپ کا بااعتماد ڈیجیٹل سیفٹی ساتھی' : 'Friendly Cyber-Safety Companion'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center text-white transition-colors cursor-pointer"
            aria-label="Close Chatbot"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Quick Resource Bar with Real Links */}
        <div className="bg-[#F8FAFC] border-b border-slate-200 px-3 py-1.5 flex items-center gap-1.5 overflow-x-auto no-scrollbar text-[10.5px]">
          <span className="text-slate-500 font-semibold shrink-0">Official Portals:</span>
          <a
            href="https://complaint.fia.gov.pk"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 bg-white hover:bg-slate-100 text-[#063E28] font-bold px-2 py-0.5 rounded-full border border-slate-200 shrink-0 no-underline"
          >
            <span>FIA Complaint Portal</span>
            <ExternalLink className="w-2.5 h-2.5 text-slate-500" />
          </a>
          <a
            href="https://fia.gov.pk"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 bg-white hover:bg-slate-100 text-[#063E28] font-bold px-2 py-0.5 rounded-full border border-slate-200 shrink-0 no-underline"
          >
            <span>FIA Official</span>
            <ExternalLink className="w-2.5 h-2.5 text-slate-500" />
          </a>
          <a
            href="tel:1991"
            className="flex items-center gap-1 bg-[#FEF2F2] hover:bg-red-100 text-[#DC2626] font-bold px-2 py-0.5 rounded-full border border-red-200 shrink-0 no-underline"
          >
            <PhoneCall className="w-2.5 h-2.5" />
            <span>Call 1991</span>
          </a>
        </div>

        {/* Messages Body */}
        <div className="flex-1 overflow-y-auto p-3.5 space-y-3 bg-[#FAF8FF]">
          {messages.map((msg, index) => (
            <div
              key={index}
              className={`flex items-start gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="w-7 h-7 rounded-lg bg-[#E6F4EA] text-[#063E28] flex items-center justify-center shrink-0 border border-[#CEEAD6] mt-0.5">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div
                className={`max-w-[82%] rounded-2xl p-3 text-xs leading-relaxed shadow-2xs ${
                  msg.role === 'user'
                    ? 'bg-[#063E28] text-white rounded-br-xs'
                    : 'bg-white text-slate-900 border border-slate-200 rounded-bl-xs'
                }`}
              >
                <p className="whitespace-pre-line">{msg.content}</p>
                {msg.time && (
                  <span
                    className={`block text-[9px] mt-1 text-right ${
                      msg.role === 'user' ? 'text-emerald-200/70' : 'text-slate-400'
                    }`}
                  >
                    {msg.time}
                  </span>
                )}
              </div>

              {msg.role === 'user' && (
                <div className="w-7 h-7 rounded-lg bg-slate-200 text-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}

          {isLoading && (
            <div className="flex items-center gap-2 text-xs text-slate-500 italic p-1">
              <div className="w-4 h-4 border-2 border-emerald-600 border-t-transparent rounded-full animate-spin" />
              <span>Cyber Saathi is consulting legal and threat databases...</span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Question Chips */}
        <div className="px-3 py-1.5 bg-slate-50 border-t border-slate-200 flex gap-1.5 overflow-x-auto no-scrollbar text-[11px]">
          {quickPrompts.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(q.prompt)}
              className="bg-white hover:bg-emerald-50 text-slate-700 hover:text-[#063E28] px-2.5 py-1 rounded-full border border-slate-200 whitespace-nowrap font-medium transition-colors cursor-pointer shrink-0"
            >
              {q.label}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-3 bg-white border-t border-slate-200 flex items-center gap-2">
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSendMessage();
            }}
            placeholder={
              currentLang === 'sd'
                ? 'ڪو به ميسيج، لنڪ، اسڪرين شاٽ يا ڪال هتي شيئر ڪريو...'
                : currentLang === 'ur'
                ? 'کوئی بھی میسج، لنک، اسکرین شاٹ یا پیشکش یہاں شیئر کریں...'
                : 'Paste a message, link, describe a screenshot or offer...'
            }
            className="flex-1 bg-[#F8FAFC] border border-slate-300 rounded-xl px-3 py-2 text-xs text-slate-900 outline-none focus:border-[#063E28] focus:ring-1 focus:ring-[#063E28]"
          />
          <button
            type="button"
            onClick={() => handleSendMessage()}
            disabled={!inputValue.trim() || isLoading}
            className="btn-tactile-primary w-9 h-9 rounded-xl flex items-center justify-center shrink-0 cursor-pointer disabled:opacity-50"
            aria-label="Send Message"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

// Re-export alias for backward compatibility
export const CyberSathiChatbot = CyberSaathiChatbot;
