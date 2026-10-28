import React from 'react';

interface CyberSaathiLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  variant?: 'shield-default' | 'shield-ai';
}

export const CyberSaathiLogo: React.FC<CyberSaathiLogoProps> = ({
  className = '',
  size = 'md',
  variant = 'shield-default',
}) => {
  const dimensions =
    size === 'sm'
      ? 'w-9 h-9'
      : size === 'lg'
      ? 'w-14 h-14'
      : size === 'xl'
      ? 'w-20 h-20'
      : 'w-10 h-10';

  return (
    <div
      className={`relative flex items-center justify-center shrink-0 ${dimensions} ${className}`}
      aria-label="Cyber Saathi Official Shield Protection Emblem"
    >
      <svg
        viewBox="0 0 120 135"
        className="w-full h-full drop-shadow-[0_4px_8px_rgba(4,42,27,0.45)] filter transition-transform duration-200 hover:scale-105"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          {/* Primary Gold Rim Multi-Stop Gradient */}
          <linearGradient id="csGoldBevel" x1="10" y1="5" x2="110" y2="130" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#FFF2B2" />
            <stop offset="20%" stopColor="#F59E0B" />
            <stop offset="45%" stopColor="#FCD34D" />
            <stop offset="75%" stopColor="#D97706" />
            <stop offset="100%" stopColor="#78350F" />
          </linearGradient>

          {/* Platinum / Metallic Accent */}
          <linearGradient id="csPlatinum" x1="20" y1="10" x2="100" y2="120" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="50%" stopColor="#E2E8F0" />
            <stop offset="100%" stopColor="#94A3B8" />
          </linearGradient>

          {/* Deep Sovereign Emerald Shield Background - Left Facet */}
          <linearGradient id="csEmeraldLeft" x1="15" y1="15" x2="60" y2="120" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#0D6E46" />
            <stop offset="50%" stopColor="#064E3B" />
            <stop offset="100%" stopColor="#022C22" />
          </linearGradient>

          {/* Deep Sovereign Emerald Shield Background - Right Facet (Darker Shadow) */}
          <linearGradient id="csEmeraldRight" x1="60" y1="15" x2="105" y2="120" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#064E3B" />
            <stop offset="60%" stopColor="#042F24" />
            <stop offset="100%" stopColor="#011812" />
          </linearGradient>

          {/* Sculpted Metallic "S" Letter Gradient */}
          <linearGradient id="csLetterS" x1="30" y1="28" x2="90" y2="105" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#FFFFFF" />
            <stop offset="25%" stopColor="#F8FAFC" />
            <stop offset="55%" stopColor="#E2E8F0" />
            <stop offset="80%" stopColor="#CBD5E1" />
            <stop offset="100%" stopColor="#94A3B8" />
          </linearGradient>

          {/* Subtle Top Specular Sheen */}
          <linearGradient id="csSheen" x1="30" y1="10" x2="90" y2="70" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0" />
          </linearGradient>

          {/* AI Glow Core for AI variant */}
          <radialGradient id="csAiCore" cx="60" cy="65" r="45" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#10B981" stopOpacity="0.4" />
            <stop offset="60%" stopColor="#064E3B" stopOpacity="0.1" />
            <stop offset="100%" stopColor="#000000" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* 1. Outer Heavy Armor Shield Silhouette with Golden Beveled Rim */}
        <path
          d="M60 4
             L106 18
             C109 20 114 46 110 75
             C105 102 78 124 60 131
             C42 124 15 102 10 75
             C6 46 11 20 14 18
             L60 4Z"
          fill="url(#csGoldBevel)"
        />

        {/* 2. Recessed Armor Inset (Dark Metallic Border) */}
        <path
          d="M60 9
             L101 21
             C104 23 108 48 104 73
             C100 97 75 117 60 124
             C45 117 20 97 16 73
             C12 48 16 23 19 21
             L60 9Z"
          fill="#021E16"
        />

        {/* 3. Left Inner Shield Plate (Light Facet) */}
        <path
          d="M60 12
             L22 23
             C19 25 15 48 19 71
             C23 93 47 112 60 119
             L60 12Z"
          fill="url(#csEmeraldLeft)"
        />

        {/* 4. Right Inner Shield Plate (Shaded Facet) */}
        <path
          d="M60 12
             L98 23
             C101 25 105 48 101 71
             C97 93 73 112 60 119
             L60 12Z"
          fill="url(#csEmeraldRight)"
        />

        {/* 5. Cyber AI Radial Glow (Subtle pulse backdrop) */}
        <path
          d="M60 12
             L98 23
             C105 48 101 71 97 93
             C73 112 60 119 60 119
             C60 119 47 112 23 93
             C19 71 15 48 22 23
             L60 12Z"
          fill="url(#csAiCore)"
        />

        {/* 6. Geometric Defense Micro-Traces (Cyber Circuit Lines) */}
        <g stroke="#34D399" strokeWidth="1" strokeOpacity="0.35" strokeLinecap="round">
          {/* Left Wing Trace */}
          <path d="M26 40 L38 40 L44 48" />
          <circle cx="26" cy="40" r="1.5" fill="#34D399" />
          <path d="M25 65 L36 65 L42 58" />
          <circle cx="25" cy="65" r="1.5" fill="#34D399" />

          {/* Right Wing Trace */}
          <path d="M94 40 L82 40 L76 48" />
          <circle cx="94" cy="40" r="1.5" fill="#34D399" />
          <path d="M95 65 L84 65 L78 58" />
          <circle cx="95" cy="65" r="1.5" fill="#34D399" />

          {/* Lower Apex Anchor */}
          <path d="M50 106 L60 114 L70 106" strokeWidth="1.2" />
        </g>

        {/* 7. Top Crest Chamfer & Center Seam Highlight */}
        <path
          d="M60 12 L60 119"
          stroke="url(#csSheen)"
          strokeWidth="1.5"
          strokeLinecap="round"
        />

        {/* 8. Iconic, Sculpted "S" Emblem (Bold, Aerodynamic & Interlocked) */}
        <g filter="drop-shadow(0 3px 5px rgba(0,0,0,0.6))">
          {/* The Unified "S" Protection Glyph */}
          <path
            d="M82 40
               C78 32 70 27 59 27
               C45 27 36 34 36 45
               C36 56 46 60 58 63
               L64 65
               C76 68 85 74 85 86
               C85 99 73 107 58 107
               C44 107 33 100 29 89
               L42 86
               C44 93 50 98 58 98
               C67 98 73 93 73 86
               C73 78 65 74 54 70
               L48 68
               C36 64 24 59 24 45
               C24 31 37 19 59 19
               C71 19 82 24 88 35
               L82 40Z"
            fill="url(#csLetterS)"
          />

          {/* Inner Sharp Angle Bevel Accent for the "S" */}
          <path
            d="M59 27 C70 27 78 32 82 40 L85 37 C80 28 70 23 59 23 Z"
            fill="#FFFFFF"
            fillOpacity="0.7"
          />
          <path
            d="M48 68 L54 70 C65 74 73 78 73 86 C73 93 67 98 58 98 L58 100 C68 100 75 94 75 86 C75 77 66 72 55 69 L48 67 Z"
            fill="#64748B"
            fillOpacity="0.5"
          />
        </g>

        {/* 9. Golden Crown Shield Star (Crest Emblem) */}
        <g filter="drop-shadow(0 1px 2px rgba(0,0,0,0.5))">
          <polygon
            points="60,6 62.5,12 68.5,12 63.5,15.5 65.5,21.5 60,18 54.5,21.5 56.5,15.5 51.5,12 57.5,12"
            fill="url(#csGoldBevel)"
          />
          <circle cx="60" cy="14" r="1.5" fill="#FFFFFF" />
        </g>

        {/* 10. Dual Crown Jewels / Cyber Corner Highlights */}
        <circle cx="16" cy="20" r="2" fill="#FCD34D" />
        <circle cx="104" cy="20" r="2" fill="#FCD34D" />
      </svg>
    </div>
  );
};

// Backwards-compatible export alias
export const CyberSathiLogo = CyberSaathiLogo;
