export interface ThreatFeedItem {
  id: string;
  iconType: 'welfare' | 'wallet' | 'blackmail' | 'utility';
  title: string;
  badge: string;
  badgeColor: 'red' | 'amber' | 'emerald';
  subtitle: string;
  quote: string;
  reportedLocation: string;
  advisory: string;
}

export const THREAT_FEED_ITEMS: ThreatFeedItem[] = [
  {
    id: 'welfare-bisp',
    iconType: 'welfare',
    title: 'Impersonation & Fake Welfare Programs',
    badge: 'HIGH RISK',
    badgeColor: 'red',
    subtitle: 'Fabricated BISP or Ehsaas grants requested from private mobile numbers',
    quote: '"Congratulations! Your CNIC has been approved for 25,000 cash grant..."',
    reportedLocation: 'Sukkur & Larkana Divisions',
    advisory: 'BISP only communicates via official shortcode 8171. Private 11-digit numbers are fraudulent.',
  },
  {
    id: 'wallet-phish',
    iconType: 'wallet',
    title: 'Unauthorized Payment & Wallet Lockouts',
    badge: 'ACCOUNT THEFT',
    badgeColor: 'amber',
    subtitle: 'Deceptive warnings that JazzCash or Easypaisa accounts are expiring',
    quote: '"Urgent: Your account is scheduled for deactivation. Confirm 4-digit PIN..."',
    reportedLocation: 'Karachi Central & Hyderabad',
    advisory: 'Financial apps never solicit MPINs or login codes over SMS or phone calls.',
  },
  {
    id: 'blackmail-extortion',
    iconType: 'blackmail',
    title: 'Blackmail & Screen Sharing Coercion',
    badge: 'FIA PRIORITY',
    badgeColor: 'emerald',
    subtitle: 'Coercive video call manipulation or intimate recording threat',
    quote: '"Send ransom to this Easypaisa number or private recording will be broadcasted..."',
    reportedLocation: 'Sindh-wide / Federal Monitoring',
    advisory: 'Never pay ransom; extortionists escalate demands. File an immediate complaint with FIA 1991.',
  },
  {
    id: 'utility-relief',
    iconType: 'utility',
    title: 'K-Electric / HESCO Bill Relief Link',
    badge: 'HIGH RISK',
    badgeColor: 'red',
    subtitle: 'Bogus tariff exemption and subsidy download forms harboring malware',
    quote: '"Claim 50% discount on October electricity bill: click bill-relief-gos.site..."',
    reportedLocation: 'Karachi & Mirpurkhas',
    advisory: 'Provincial power subsidies are reflected directly on official utility bills, never via third-party web forms.',
  },
];
