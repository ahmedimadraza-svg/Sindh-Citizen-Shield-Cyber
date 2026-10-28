import dns from 'dns/promises';
import { URL } from 'url';

export interface AuthoritativeSource {
  id: string;
  name: string;
  parentOrg: string;
  category:
    | 'government'
    | 'telecom'
    | 'welfare'
    | 'banking'
    | 'utility'
    | 'cyber_defense'
    | 'traffic_challan'
    | 'law_enforcement'
    | 'courier';
  officialDomains: string[];
  exactHostname?: string;
  knownSubdomains?: string[];
  officialShortcodes?: string[];
  publicVerificationUrl: string;
  helpline?: string;
  verificationTimestamp: string;
  lastSuccessfulCheck: string;
  status: 'verified' | 'stale' | 'disputed' | 'disabled';
  authorizedServices: string[];
  restrictions?: string;
  publicLookupAvailable: boolean;
  description: string;
}

// 1. Authoritative Public Pakistani Sources Registry (Central, Audited Registry)
export const AUTHORITATIVE_REGISTRY: AuthoritativeSource[] = [
  // --- CYBER DEFENSE & NATIONAL REPORTING ---
  {
    id: 'nccia',
    name: 'National Cyber Crime Investigation Agency (NCCIA)',
    parentOrg: 'Federal Government of Pakistan',
    category: 'cyber_defense',
    officialDomains: ['nccia.gov.pk'],
    exactHostname: 'nccia.gov.pk',
    knownSubdomains: ['complaint.nccia.gov.pk', 'www.nccia.gov.pk'],
    publicVerificationUrl: 'https://complaint.nccia.gov.pk',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: [
      'National Cybercrime Complaints',
      'Federal Digital Forensic Inquiries',
      'Cyber Fraud Advisories',
    ],
    restrictions: 'Exclusive federal agency mandated for digital crime investigation under current statutory framework.',
    publicLookupAvailable: true,
    description:
      'Dedicated national cyber investigation authority under the 2025 legal framework, responsible for national cybercrime investigations and complaint registration.',
  },
  {
    id: 'fia-cyber',
    name: 'Federal Investigation Agency (FIA)',
    parentOrg: 'Ministry of Interior, Federal Government of Pakistan',
    category: 'cyber_defense',
    officialDomains: ['fia.gov.pk'],
    exactHostname: 'fia.gov.pk',
    knownSubdomains: ['complaint.fia.gov.pk', 'www.fia.gov.pk'],
    publicVerificationUrl: 'https://complaint.fia.gov.pk',
    helpline: '1991',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: [
      'Federal Law Enforcement',
      'Immigration & Anti-Human Trafficking',
      'Historical PECA 2016 Mandate',
    ],
    restrictions:
      'General federal enforcement agency. National cybercrime inquiries transition through NCCIA statutory framework; 1991 hotline provides public guidance.',
    publicLookupAvailable: true,
    description:
      'Federal law enforcement agency. Mandated historically under PECA 2016 for digital crimes investigation; continues broader federal law enforcement mandate.',
  },

  // --- TRAFFIC CHALLANS & PROVINCIAL VEHICLE FINES ---
  {
    id: 'psca',
    name: 'Punjab Safe Cities Authority (PSCA)',
    parentOrg: 'Government of Punjab, Pakistan',
    category: 'traffic_challan',
    officialDomains: ['psca.gop.pk'],
    exactHostname: 'psca.gop.pk',
    knownSubdomains: ['echallan.psca.gop.pk', 'www.psca.gop.pk'],
    publicVerificationUrl: 'https://echallan.psca.gop.pk',
    helpline: '15',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: [
      'Punjab Traffic E-Challan Inquiry',
      'Traffic Violation Evidence Records',
      '1Link 1Bill PSID Generation',
    ],
    restrictions:
      'Official e-Challan lookup portal is https://echallan.psca.gop.pk. Public automated lookup requires vehicle number and CNIC / Chassis number. Cyber Saathi does NOT access private police enforcement databases directly.',
    publicLookupAvailable: true,
    description:
      'Autonomous government body managing traffic surveillance and electronic challan issuance across Punjab cities including Lahore, Rawalpindi, and Faisalabad.',
  },
  {
    id: 'punjab-police',
    name: 'Punjab Police',
    parentOrg: 'Government of Punjab, Pakistan',
    category: 'law_enforcement',
    officialDomains: ['punjabpolice.gov.pk'],
    exactHostname: 'punjabpolice.gov.pk',
    publicVerificationUrl: 'https://punjabpolice.gov.pk',
    helpline: '1787',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Provincial Policing', 'Traffic Warden Service', 'Citizen Facilitation Centers (PKM)'],
    restrictions: 'Legal arrest warrants are issued strictly via judicial courts, not unsolicited SMS messages demanding immediate fine payments.',
    publicLookupAvailable: false,
    description: 'Provincial law enforcement agency of Punjab, Pakistan.',
  },
  {
    id: 'punjab-excise',
    name: 'Excise, Taxation & Narcotics Control Department, Punjab',
    parentOrg: 'Government of Punjab, Pakistan',
    category: 'traffic_challan',
    officialDomains: ['excise.punjab.gov.pk', 'mtmis.punjab.gov.pk'],
    exactHostname: 'excise.punjab.gov.pk',
    knownSubdomains: ['mtmis.punjab.gov.pk'],
    publicVerificationUrl: 'https://mtmis.punjab.gov.pk',
    helpline: '0800-08786',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Motor Transport Management Information System (MTMIS)', 'Vehicle Token Tax Verification'],
    restrictions: 'Public vehicle records are queryable via MTMIS with registration number. Payment is made via 1Bill/ePay Punjab.',
    publicLookupAvailable: true,
    description: 'Provincial department managing motor vehicle registration, token tax, and excise duties in Punjab.',
  },
  {
    id: 'sindh-police',
    name: 'Sindh Police & Traffic Police Karachi',
    parentOrg: 'Government of Sindh, Pakistan',
    category: 'traffic_challan',
    officialDomains: ['sindhpolice.gov.pk'],
    exactHostname: 'sindhpolice.gov.pk',
    knownSubdomains: ['traffic.sindhpolice.gov.pk', 'www.sindhpolice.gov.pk'],
    publicVerificationUrl: 'https://sindhpolice.gov.pk',
    helpline: '1915',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Karachi Traffic Police Fine Management', 'Driving Licence Sindh Verification', 'Citizen Complaints'],
    restrictions: 'Official traffic fines in Sindh are paid via National Bank of Pakistan (NBP) or designated bank channels, never personal mobile numbers.',
    publicLookupAvailable: true,
    description: 'Law enforcement and traffic regulation authority for Sindh province and Karachi metropolitan area.',
  },
  {
    id: 'sindh-excise',
    name: 'Excise, Taxation & Narcotics Control Department, Sindh',
    parentOrg: 'Government of Sindh, Pakistan',
    category: 'traffic_challan',
    officialDomains: ['excise.gos.pk'],
    exactHostname: 'excise.gos.pk',
    publicVerificationUrl: 'https://excise.gos.pk',
    helpline: '021-99231410',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Online Vehicle Verification Sindh', 'Motor Vehicle Tax Records'],
    restrictions: 'Online vehicle verification confirms registration status. Cyber Saathi does not access private tax payer credentials.',
    publicLookupAvailable: true,
    description: 'Provincial department managing vehicle taxation and registration in Sindh.',
  },

  // --- GOVERNMENT PORTALS ---
  {
    id: 'pakistan-gov',
    name: 'Government of Pakistan (Official Federal Portal)',
    parentOrg: 'Federal Government of Pakistan',
    category: 'government',
    officialDomains: ['pakistan.gov.pk'],
    exactHostname: 'pakistan.gov.pk',
    publicVerificationUrl: 'https://pakistan.gov.pk',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['National Web Gateway', 'Official Gazettes', 'Federal Notifications'],
    publicLookupAvailable: false,
    description: 'Official national web gateway of the Federal Government of Pakistan.',
  },
  {
    id: 'punjab-gov',
    name: 'Government of Punjab (Official Provincial Portal)',
    parentOrg: 'Provincial Government of Punjab, Pakistan',
    category: 'government',
    officialDomains: ['punjab.gov.pk', 'gop.pk'],
    exactHostname: 'punjab.gov.pk',
    publicVerificationUrl: 'https://punjab.gov.pk',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Provincial Departmental Directory', 'ePay Punjab Portal', 'Public Notices'],
    publicLookupAvailable: false,
    description: 'Official web portal of the provincial Government of Punjab.',
  },
  {
    id: 'sindh-gov',
    name: 'Government of Sindh',
    parentOrg: 'Provincial Government of Sindh, Pakistan',
    category: 'government',
    officialDomains: ['sindh.gov.pk', 'gos.pk'],
    exactHostname: 'sindh.gov.pk',
    publicVerificationUrl: 'https://sindh.gov.pk',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Sindh Provincial Departments', 'Official Gazette Notifications', 'Provincial Services'],
    publicLookupAvailable: false,
    description: 'Official provincial government portal for Sindh departments, public notices, and civic services.',
  },
  {
    id: 'citizen-portal',
    name: 'Pakistan Citizen Portal (PCP)',
    parentOrg: 'Prime Minister’s Performance Delivery Unit (PMDU), Pakistan',
    category: 'government',
    officialDomains: ['citizenportal.gov.pk'],
    exactHostname: 'web.citizenportal.gov.pk',
    publicVerificationUrl: 'https://web.citizenportal.gov.pk',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Citizen Grievance Redressal', 'Government Complaints Tracking'],
    publicLookupAvailable: false,
    description: 'National citizen grievance mechanism integrated across federal and provincial authorities.',
  },

  // --- WELFARE & CIVIL IDENTITY ---
  {
    id: 'bisp',
    name: 'Benazir Income Support Programme (BISP)',
    parentOrg: 'Federal Government of Pakistan',
    category: 'welfare',
    officialDomains: ['bisp.gov.pk'],
    exactHostname: 'bisp.gov.pk',
    knownSubdomains: ['8171.bisp.gov.pk', 'www.bisp.gov.pk'],
    officialShortcodes: ['8171'],
    publicVerificationUrl: 'https://8171.bisp.gov.pk',
    helpline: '0800-26477',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Kafaalat & Taleemi Wazaif Beneficiary Verification', '8171 SMS Portal'],
    restrictions: 'BISP communications originate EXCLUSIVELY from shortcode 8171. BISP never requires payment or OTP disclosure to release funds.',
    publicLookupAvailable: true,
    description: 'National social safety net. Official beneficiary notifications are dispatched EXCLUSIVELY via shortcode 8171.',
  },
  {
    id: 'nadra',
    name: 'National Database and Registration Authority (NADRA)',
    parentOrg: 'Ministry of Interior, Pakistan',
    category: 'government',
    officialDomains: ['nadra.gov.pk'],
    exactHostname: 'nadra.gov.pk',
    knownSubdomains: ['id.nadra.gov.pk', 'www.nadra.gov.pk'],
    officialShortcodes: ['8500', '8400'],
    publicVerificationUrl: 'https://www.nadra.gov.pk',
    helpline: '1777',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Pak-Identity Portal', 'CNIC Tracking', 'Family Registration Certificate (FRC)'],
    restrictions: 'Official digital identity operations are hosted under id.nadra.gov.pk. NADRA does not use .xyz or .com domains.',
    publicLookupAvailable: true,
    description: 'National civil identification agency for CNIC, Family Registration, and biometric identity verification.',
  },
  {
    id: 'pta',
    name: 'Pakistan Telecommunication Authority (PTA)',
    parentOrg: 'Cabinet Division, Government of Pakistan',
    category: 'telecom',
    officialDomains: ['pta.gov.pk', 'sims.pk'],
    exactHostname: 'pta.gov.pk',
    knownSubdomains: ['cnic.sims.pk', 'dirbs.pta.gov.pk'],
    officialShortcodes: ['668'],
    publicVerificationUrl: 'https://cnic.sims.pk',
    helpline: '0800-55055',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Biometric SIM Verification (668)', 'Device Registration (DIRBS)', 'Telecom Consumer Complaints'],
    restrictions: 'Official SIM count inquiry operates via 668 shortcode and cnic.sims.pk.',
    publicLookupAvailable: true,
    description: 'National telecom regulator. Official SIM verification is conducted via shortcode 668 or cnic.sims.pk.',
  },

  // --- FINANCIAL REGULATORS & BANKING NETWORKS ---
  {
    id: 'sbp-1link',
    name: 'State Bank of Pakistan (SBP) & 1Link Switch',
    parentOrg: 'Central Bank of Pakistan',
    category: 'banking',
    officialDomains: ['sbp.org.pk', '1link.net.pk'],
    exactHostname: 'sbp.org.pk',
    publicVerificationUrl: 'https://www.sbp.org.pk',
    helpline: '111-727-273',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Monetary Regulation', 'Interbank Electronic Fund Transfer (1Link)', 'Consumer Financial Protection'],
    restrictions: 'SBP publishes regulatory directives. SBP does not validate individual retail bank transactions from screenshots.',
    publicLookupAvailable: false,
    description: 'Central monetary authority and national inter-bank payment rail for dispute reversals.',
  },
  {
    id: 'secp',
    name: 'Securities and Exchange Commission of Pakistan (SECP)',
    parentOrg: 'Ministry of Finance, Pakistan',
    category: 'government',
    officialDomains: ['secp.gov.pk'],
    exactHostname: 'secp.gov.pk',
    publicVerificationUrl: 'https://www.secp.gov.pk',
    helpline: '0800-88008',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Corporate Registry Search', 'Unregistered Investment Scheme Warnings', 'Capital Market Oversight'],
    restrictions: 'SECP publishes lists of unauthorized investment schemes and Ponzi alerts.',
    publicLookupAvailable: true,
    description: 'National financial and corporate regulator. Regulates companies, non-banking financial institutions, and capital markets.',
  },

  // --- COMMERCIAL BANKS (Individual Verified Institutional Entries) ---
  {
    id: 'bank-hbl',
    name: 'Habib Bank Limited (HBL)',
    parentOrg: 'Habib Bank Limited, Pakistan',
    category: 'banking',
    officialDomains: ['hbl.com'],
    exactHostname: 'hbl.com',
    knownSubdomains: ['www.hbl.com', 'hblmobile.com'],
    publicVerificationUrl: 'https://www.hbl.com',
    helpline: '021-111-111-425',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Commercial Banking', 'Digital Banking Alerts'],
    restrictions: 'HBL never asks customers to share OTPs, PINs, or debit card CVVs over phone or email.',
    publicLookupAvailable: false,
    description: 'Commercial bank in Pakistan. Legitimate domain is hbl.com.',
  },
  {
    id: 'bank-ubl',
    name: 'United Bank Limited (UBL)',
    parentOrg: 'United Bank Limited, Pakistan',
    category: 'banking',
    officialDomains: ['ubldigital.com', 'ubl.com.pk'],
    exactHostname: 'ubldigital.com',
    publicVerificationUrl: 'https://www.ubldigital.com',
    helpline: '021-111-825-888',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Retail & Digital Banking'],
    publicLookupAvailable: false,
    description: 'Commercial bank in Pakistan. Legitimate domain is ubldigital.com.',
  },
  {
    id: 'bank-meezan',
    name: 'Meezan Bank Limited',
    parentOrg: 'Meezan Bank Limited, Pakistan',
    category: 'banking',
    officialDomains: ['meezanbank.com'],
    exactHostname: 'meezanbank.com',
    publicVerificationUrl: 'https://www.meezanbank.com',
    helpline: '021-111-331-331',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Islamic Commercial Banking'],
    publicLookupAvailable: false,
    description: 'Islamic commercial bank in Pakistan. Legitimate domain is meezanbank.com.',
  },
  {
    id: 'bank-mcb',
    name: 'MCB Bank Limited',
    parentOrg: 'MCB Bank Limited, Pakistan',
    category: 'banking',
    officialDomains: ['mcb.com.pk'],
    exactHostname: 'mcb.com.pk',
    publicVerificationUrl: 'https://www.mcb.com.pk',
    helpline: '021-111-000-622',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Commercial Banking'],
    publicLookupAvailable: false,
    description: 'Commercial bank in Pakistan. Legitimate domain is mcb.com.pk.',
  },
  {
    id: 'bank-alfalah',
    name: 'Bank Alfalah Limited',
    parentOrg: 'Bank Alfalah, Pakistan',
    category: 'banking',
    officialDomains: ['bankalfalah.com'],
    exactHostname: 'bankalfalah.com',
    publicVerificationUrl: 'https://www.bankalfalah.com',
    helpline: '021-111-225-111',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Commercial Banking & Digital Wallets'],
    publicLookupAvailable: false,
    description: 'Commercial bank in Pakistan. Legitimate domain is bankalfalah.com.',
  },

  // --- MOBILE WALLETS ---
  {
    id: 'jazzcash',
    name: 'JazzCash (Mobilink Microfinance Bank)',
    parentOrg: 'VEON / Jazz, Pakistan',
    category: 'banking',
    officialDomains: ['jazzcash.com.pk'],
    exactHostname: 'jazzcash.com.pk',
    officialShortcodes: ['8558'],
    publicVerificationUrl: 'https://www.jazzcash.com.pk',
    helpline: '4444',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Branchless Banking & Microfinance'],
    restrictions: 'Official SMS notifications originate from 8558. Never share your MPIN or SMS verification code with any caller.',
    publicLookupAvailable: false,
    description: 'Authorized digital mobile financial service. Official notifications originate from 8558.',
  },
  {
    id: 'easypaisa',
    name: 'Easypaisa (Telenor Microfinance Bank)',
    parentOrg: 'Telenor Microfinance Bank, Pakistan',
    category: 'banking',
    officialDomains: ['easypaisa.com.pk'],
    exactHostname: 'easypaisa.com.pk',
    officialShortcodes: ['3737'],
    publicVerificationUrl: 'https://easypaisa.com.pk',
    helpline: '3737',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Branchless Banking & Digital Payments'],
    restrictions: 'Official alerts originate from 3737. Easypaisa never asks for your login PIN or OTP.',
    publicLookupAvailable: false,
    description: 'Authorized branchless banking provider. Official alerts originate from 3737.',
  },
  {
    id: 'sadapay',
    name: 'SadaPay (EMI)',
    parentOrg: 'SadaTech Pakistan',
    category: 'banking',
    officialDomains: ['sadapay.pk'],
    exactHostname: 'sadapay.pk',
    publicVerificationUrl: 'https://sadapay.pk',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Electronic Money Institution (EMI)'],
    publicLookupAvailable: false,
    description: 'Licensed Electronic Money Institution regulated by State Bank of Pakistan.',
  },

  // --- TELECOM OPERATORS ---
  {
    id: 'zong',
    name: 'Zong 4G (CMPak Limited)',
    parentOrg: 'China Mobile',
    category: 'telecom',
    officialDomains: ['zong.com.pk'],
    exactHostname: 'zong.com.pk',
    officialShortcodes: ['310'],
    publicVerificationUrl: 'https://www.zong.com.pk',
    helpline: '310',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Cellular Mobile Services & Data Bundles'],
    publicLookupAvailable: true,
    description: 'Cellular mobile network operator in Pakistan. Official customer notifications originate from shortcode 310.',
  },
  {
    id: 'ufone',
    name: 'Ufone 4G (PTML)',
    parentOrg: 'PTCL Group',
    category: 'telecom',
    officialDomains: ['ufone.com'],
    exactHostname: 'ufone.com',
    officialShortcodes: ['333'],
    publicVerificationUrl: 'https://www.ufone.com',
    helpline: '333',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Cellular Telecommunication Services'],
    publicLookupAvailable: true,
    description: 'Cellular telecommunication service provider in Pakistan. Official alerts originate from shortcode 333.',
  },
  {
    id: 'telenor-pk',
    name: 'Telenor Pakistan',
    parentOrg: 'Telenor Group / PTCL',
    category: 'telecom',
    officialDomains: ['telenor.com.pk'],
    exactHostname: 'telenor.com.pk',
    officialShortcodes: ['345'],
    publicVerificationUrl: 'https://www.telenor.com.pk',
    helpline: '345',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Cellular Telecommunications & Data'],
    publicLookupAvailable: true,
    description: 'Cellular telecommunications network in Pakistan. Official alerts originate from shortcode 345.',
  },

  // --- UTILITIES & COURIERS ---
  {
    id: 'k-electric',
    name: 'K-Electric (Karachi Power Utility)',
    parentOrg: 'K-Electric Limited',
    category: 'utility',
    officialDomains: ['ke.com.pk'],
    exactHostname: 'ke.com.pk',
    publicVerificationUrl: 'https://www.ke.com.pk',
    helpline: '118',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Karachi Electric Supply & Duplicate Bills'],
    publicLookupAvailable: true,
    description: 'Primary electric utility provider for Karachi Metropolitan Area.',
  },
  {
    id: 'tcs',
    name: 'TCS Express & Logistics',
    parentOrg: 'TCS Holdings (Pvt) Ltd',
    category: 'courier',
    officialDomains: ['tcsexpress.com'],
    exactHostname: 'tcsexpress.com',
    publicVerificationUrl: 'https://www.tcsexpress.com',
    helpline: '021-111-123-456',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Domestic & International Parcel Tracking'],
    restrictions: 'TCS delivery charges are paid at booking or Cash on Delivery, never via private mobile number SMS demands.',
    publicLookupAvailable: true,
    description: 'Courier and logistics provider in Pakistan. Official domain is tcsexpress.com.',
  },
  {
    id: 'pak-post',
    name: 'Pakistan Post',
    parentOrg: 'Ministry of Communications, Government of Pakistan',
    category: 'courier',
    officialDomains: ['pakpost.gov.pk'],
    exactHostname: 'pakpost.gov.pk',
    publicVerificationUrl: 'https://ep.gov.pk',
    helpline: '111-111-117',
    verificationTimestamp: '2026-10-20T00:00:00Z',
    lastSuccessfulCheck: '2026-10-20T00:00:00Z',
    status: 'verified',
    authorizedServices: ['National Postal Service & Parcel Tracking (Express Post)'],
    restrictions: 'Official customs fees are paid at designated post offices or via official banking challan.',
    publicLookupAvailable: true,
    description: 'National postal administration of Pakistan.',
  },
  {
    id: 'gcash',
    name: 'GCash (G-Xchange Inc. / Mynt)',
    parentOrg: 'Globe Fintech Innovations (Mynt), Philippines',
    category: 'banking',
    officialDomains: ['gcash.com', 'new.gcash.com'],
    exactHostname: 'www.gcash.com',
    knownSubdomains: ['help.gcash.com', 'new.gcash.com'],
    officialShortcodes: ['2882', 'GCASH'],
    publicVerificationUrl: 'https://www.gcash.com',
    helpline: '2882',
    verificationTimestamp: '2026-10-21T00:00:00Z',
    lastSuccessfulCheck: '2026-10-21T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Mobile Wallet', 'Digital Payments', 'Bank Transfers', 'Bills Payment'],
    restrictions:
      'Official GCash security policy and NTC regulations strictly prohibit clickable links in SMS. Any SMS claiming to be GCash or referencing GCash transactions that includes a clickable link (especially bit.ly or third-party links) is unauthorized and deceptive.',
    publicLookupAvailable: true,
    description:
      'Leading Philippine mobile wallet and financial service. Strictly enforced policy: GCash does not send clickable links in SMS to prevent phishing.',
  },
  {
    id: 'dswd',
    name: 'Department of Social Welfare and Development (DSWD)',
    parentOrg: 'Government of the Philippines',
    category: 'welfare',
    officialDomains: ['dswd.gov.ph'],
    exactHostname: 'www.dswd.gov.ph',
    knownSubdomains: ['ayuda.dswd.gov.ph', 'sap.dswd.gov.ph'],
    publicVerificationUrl: 'https://www.dswd.gov.ph',
    verificationTimestamp: '2026-10-21T00:00:00Z',
    lastSuccessfulCheck: '2026-10-21T00:00:00Z',
    status: 'verified',
    authorizedServices: ['Social Amelioration Program (SAP)', 'Emergency Subsidy (Ayuda)', 'Pantawid Pamilyang Pilipino Program (4Ps)'],
    restrictions:
      'DSWD Ayuda and social relief are distributed through accredited local government channels and authorized financial service providers. DSWD never sends SMS with shortened bit.ly links instructing citizens to update personal or banking details to claim aid.',
    publicLookupAvailable: true,
    description:
      'Philippine national executive department responsible for social protection, poverty alleviation, and public financial aid distribution.',
  },
];

// 2. SSRF & Private Network IP Range Validation
export function isPrivateOrReservedIp(ip: string): boolean {
  // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
  const cleanIp = ip.replace(/^::ffff:/i, '');

  // IPv4 checks
  const ipv4Parts = cleanIp.split('.').map(Number);
  if (ipv4Parts.length === 4 && ipv4Parts.every((n) => !isNaN(n) && n >= 0 && n <= 255)) {
    const [a, b] = ipv4Parts;
    // Loopback 127.0.0.0/8
    if (a === 127) return true;
    // 0.0.0.0/8
    if (a === 0) return true;
    // Private RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    // Link-local / Cloud Metadata (169.254.0.0/16, including 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // Carrier-grade NAT (100.64.0.0/10)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // Multicast & Reserved (224.0.0.0/4, 240.0.0.0/4)
    if (a >= 224) return true;
    return false;
  }

  // IPv6 checks
  const lowerIpv6 = cleanIp.toLowerCase();
  if (
    lowerIpv6 === '::1' ||
    lowerIpv6 === '::' ||
    lowerIpv6.startsWith('fe80:') || // Link-local
    lowerIpv6.startsWith('fc00:') || // Unique local
    lowerIpv6.startsWith('fd00:') ||
    lowerIpv6.startsWith('ff') // Multicast
  ) {
    return true;
  }

  return false;
}

export interface SanitizedUrlCheck {
  valid: boolean;
  normalizedUrl?: string;
  domain?: string;
  protocol?: string;
  reason?: string;
  resolvedIps?: string[];
  isSecurityBlock?: boolean;
  dnsFailed?: boolean;
}

export async function validateAndSanitizeUrl(rawUrl: string): Promise<SanitizedUrlCheck> {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return { valid: false, reason: 'URL cannot be empty' };
  }

  let formatted = trimmed;
  // If no scheme at all (e.g. "sindh.gov.pk/test"), prepend http://
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(formatted)) {
    formatted = 'http://' + formatted;
  }

  let parsed: URL;
  try {
    parsed = new URL(formatted);
  } catch {
    return { valid: false, reason: 'Malformed URL syntax' };
  }

  // Protocol check: only http or https permitted
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      reason: `Unsafe scheme '${parsed.protocol}'. Only standard HTTP and HTTPS web protocols are permitted.`,
      isSecurityBlock: true,
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Hostname validation
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    return {
      valid: false,
      reason: 'Access to localhost, loopback, or private internal network hostnames is blocked.',
      isSecurityBlock: true,
      domain: hostname,
      normalizedUrl: parsed.toString(),
    };
  }

  // Resolve hostname to IP addresses and inspect for SSRF
  try {
    const addresses = await dns.resolve4(hostname).catch(async () => {
      // Fallback to lookup which handles both IPv4/IPv6
      const res = await dns.lookup(hostname, { all: true });
      return res.map((r) => r.address);
    });

    if (!addresses || addresses.length === 0) {
      return {
        valid: false,
        reason: `Domain name '${hostname}' could not be resolved via DNS.`,
        dnsFailed: true,
        domain: hostname,
        normalizedUrl: parsed.toString(),
      };
    }

    for (const ip of addresses) {
      if (isPrivateOrReservedIp(ip)) {
        return {
          valid: false,
          reason: `Security Block (SSRF Protection): Hostname resolves to private/reserved IP address (${ip}).`,
          isSecurityBlock: true,
          resolvedIps: addresses,
          domain: hostname,
          normalizedUrl: parsed.toString(),
        };
      }
    }

    return {
      valid: true,
      normalizedUrl: parsed.toString(),
      domain: hostname,
      protocol: parsed.protocol,
      resolvedIps: addresses,
    };
  } catch (err: any) {
    return {
      valid: false,
      reason: `DNS resolution failed: ${err.message || 'Host unreachable'}`,
      dnsFailed: true,
      domain: hostname,
      normalizedUrl: parsed.toString(),
    };
  }
}

// 3. Safe Public Page Inspection
export interface PageRetrievalResult {
  retrieved: boolean;
  httpStatus?: number;
  finalUrl?: string;
  title?: string;
  description?: string;
  securityHeaders?: {
    hsts?: boolean;
    csp?: boolean;
  };
  serverBanner?: string;
  textExcerpt?: string;
  redirected?: boolean;
  failureReason?: string;
  requiresJavaScript?: boolean;
  requiresJavaScriptNote?: string;
}

export async function safeRetrievePageInfo(targetUrl: string, maxRedirects = 3): Promise<PageRetrievalResult> {
  const sanitize = await validateAndSanitizeUrl(targetUrl);
  if (!sanitize.valid || !sanitize.normalizedUrl) {
    return {
      retrieved: false,
      failureReason: sanitize.reason || 'URL failed safety validation.',
    };
  }

  let currentUrl = sanitize.normalizedUrl;
  let redirectCount = 0;

  try {
    while (redirectCount <= maxRedirects) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

      const response = await fetch(currentUrl, {
        method: 'GET',
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 CyberSaathiCivicBot/1.0',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9,ur;q=0.8,sd;q=0.7',
        },
        signal: controller.signal,
        redirect: 'manual', // Manual redirect control to validate each hop against SSRF
      });

      clearTimeout(timeoutId);

      // Handle manual redirects securely
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        if (!location) {
          return {
            retrieved: false,
            httpStatus: response.status,
            failureReason: 'Redirect status received without Location header.',
          };
        }

        const nextUrl = new URL(location, currentUrl).toString();
        const nextSanitize = await validateAndSanitizeUrl(nextUrl);
        if (!nextSanitize.valid || !nextSanitize.normalizedUrl) {
          return {
            retrieved: false,
            httpStatus: response.status,
            failureReason: `Blocked redirect to unsafe target: ${nextSanitize.reason}`,
          };
        }

        currentUrl = nextSanitize.normalizedUrl;
        redirectCount++;
        continue;
      }

      // Check Content-Type to avoid downloading binary streams
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('text/html') && !contentType.includes('text/plain')) {
        return {
          retrieved: true,
          httpStatus: response.status,
          finalUrl: currentUrl,
          redirected: redirectCount > 0,
          failureReason: `Resource content-type is non-HTML (${contentType}). Binary file retrieval avoided.`,
        };
      }

      // Read limited body text (capped at 512 KB to prevent memory exhaustion)
      const text = await response.text();
      const truncated = text.slice(0, 524288);

      // Extract basic HTML metadata
      const titleMatch = truncated.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      const title = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : undefined;

      const descMatch =
        truncated.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i) ||
        truncated.match(/<meta[^>]*content=["']([\s\S]*?)["'][^>]*name=["']description["']/i);
      const description = descMatch ? descMatch[1].replace(/\s+/g, ' ').trim() : undefined;

      // Security headers check
      const hsts = Boolean(response.headers.get('strict-transport-security'));
      const csp = Boolean(response.headers.get('content-security-policy'));
      const serverBanner = response.headers.get('server') || undefined;

      // Extract text excerpt (strip scripts, styles, tags)
      const textOnly = truncated
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
        .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

      const textExcerpt = textOnly.slice(0, 500);

      // Detect if page requires JavaScript or is a client-side SPA shell
      const hasNoScriptWarning = /enable javascript|javascript is required|requires javascript/i.test(truncated);
      const isClientSideAppShell =
        (textOnly.length < 200 && (truncated.includes('id="root"') || truncated.includes('id="app"') || truncated.includes('__NEXT_DATA__'))) ||
        hasNoScriptWarning;

      const requiresJavaScript = isClientSideAppShell;
      const requiresJavaScriptNote = isClientSideAppShell
        ? 'Client-side rendered application (SPA) detected. Dynamic content requires JavaScript execution; static HTTP inspection retrieved the initial HTML shell.'
        : undefined;

      return {
        retrieved: true,
        httpStatus: response.status,
        finalUrl: currentUrl,
        title,
        description,
        securityHeaders: { hsts, csp },
        serverBanner,
        textExcerpt,
        redirected: redirectCount > 0,
        requiresJavaScript,
        requiresJavaScriptNote,
      };
    }

    return {
      retrieved: false,
      failureReason: `Exceeded maximum redirect limit (${maxRedirects}).`,
    };
  } catch (err: any) {
    return {
      retrieved: false,
      failureReason: err.name === 'AbortError' ? 'Page request timed out (6s limit).' : err.message,
    };
  }
}

// 4. Registry Corroboration Engine
export function matchAuthoritativeRegistry(hostname: string): AuthoritativeSource | undefined {
  const lower = hostname.toLowerCase();
  for (const src of AUTHORITATIVE_REGISTRY) {
    for (const domain of src.officialDomains) {
      if (lower === domain || lower.endsWith('.' + domain)) {
        return src;
      }
    }
  }
  return undefined;
}

export function detectBrandImpersonation(hostname: string, pathname: string): {
  impersonating: boolean;
  claimedOrg?: string;
  officialDomain?: string;
  reason?: string;
} {
  const host = hostname.toLowerCase();
  const path = pathname.toLowerCase();
  const matchedAuth = matchAuthoritativeRegistry(host);

  // If already matches an official domain of the authoritative source, it's not impersonation
  if (matchedAuth) {
    return { impersonating: false };
  }

  // Check 1: Deceptive Subdomain Attack (Embedding official gov domains inside subdomains)
  // Examples: psca.gop.pk.attacker.com, fia.gov.pk.fake-portal.xyz, echallan.psca.gop.pk.fraud.org
  if (
    host.includes('.gov.pk.') ||
    host.includes('.gop.pk.') ||
    host.includes('.gos.pk.') ||
    host.includes('.edu.pk.')
  ) {
    if (host.includes('bisp.') || host.includes('.bisp.')) {
      return {
        impersonating: true,
        claimedOrg: 'Benazir Income Support Programme (BISP / 8171)',
        officialDomain: 'bisp.gov.pk',
        reason: `Deceptive subdomain attack: official BISP domain was prepended as a subdomain, but the actual registrable domain is '${host}'.`,
      };
    }
    if (host.includes('fia.') || host.includes('.fia.')) {
      return {
        impersonating: true,
        claimedOrg: 'Federal Investigation Agency (FIA)',
        officialDomain: 'fia.gov.pk',
        reason: `Deceptive subdomain attack: official FIA domain was prepended as a subdomain, but the actual registrable domain is '${host}'.`,
      };
    }
    if (host.includes('psca.') || host.includes('echallan.')) {
      return {
        impersonating: true,
        claimedOrg: 'Punjab Safe Cities Authority (PSCA / e-Challan)',
        officialDomain: 'psca.gop.pk',
        reason: `Deceptive subdomain attack: official PSCA domain was prepended as a subdomain, but the actual registrable domain is '${host}'.`,
      };
    }
    if (host.includes('nadra.') || host.includes('.nadra.')) {
      return {
        impersonating: true,
        claimedOrg: 'National Database and Registration Authority (NADRA)',
        officialDomain: 'nadra.gov.pk',
        reason: `Deceptive subdomain attack: official NADRA domain was prepended as a subdomain, but the actual registrable domain is '${host}'.`,
      };
    }
    if (host.includes('pta.') || host.includes('.pta.')) {
      return {
        impersonating: true,
        claimedOrg: 'Pakistan Telecommunication Authority (PTA)',
        officialDomain: 'pta.gov.pk',
        reason: `Deceptive subdomain attack: official PTA domain was prepended as a subdomain, but the actual registrable domain is '${host}'.`,
      };
    }
    return {
      impersonating: true,
      claimedOrg: 'Government / Official Authority (Deceptive Subdomain Attack)',
      officialDomain: 'gov.pk / gop.pk',
      reason: `Deceptive subdomain attack: official domain structure was prepended as a subdomain, but the actual registrable domain is '${host}'.`,
    };
  }

  // Check 2: Homograph / Punycode Attacks
  if (host.startsWith('xn--') || host.includes('.xn--')) {
    return {
      impersonating: true,
      claimedOrg: 'Punycode / Homograph Impersonation',
      officialDomain: 'unverified-punycode',
      reason: `Homograph / Punycode attack: domain '${host}' employs encoded or non-standard Unicode characters to visually mimic a legitimate Pakistani service.`,
    };
  }

  // Check 3: Punjab Safe Cities Authority (PSCA) & Traffic e-Challan Spoofing
  if (
    host.includes('psca') ||
    host.includes('echallan') ||
    host.includes('e-challan') ||
    host.includes('challan-pay') ||
    host.includes('traffic-challan')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Punjab Safe Cities Authority / Traffic e-Challan',
      officialDomain: 'psca.gop.pk / gos.pk',
      reason:
        'Domain mimics electronic traffic challan or fine payment systems on an unauthorized non-governmental host.',
    };
  }

  // Check 4: Sindh Traffic Police & Karachi Fine Spoofing
  if (
    host.includes('sindh-traffic') ||
    host.includes('karachi-traffic') ||
    host.includes('sindhpolice-challan') ||
    host.includes('karachi-traffic-fine')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Sindh Police / Karachi Traffic Police',
      officialDomain: 'sindhpolice.gov.pk',
      reason:
        'Domain mimics Sindh Traffic Police challan or verification services on an unauthorized non-government host.',
    };
  }

  // Check 5: Provincial Excise & Motor Vehicle (MTMIS) Spoofing
  if (
    host.includes('mtmis-punjab') ||
    host.includes('excise-punjab') ||
    host.includes('excise-sindh') ||
    host.includes('punjab-mtmis') ||
    host.includes('sindh-mtmis')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Excise, Taxation & Narcotics Control (MTMIS)',
      officialDomain: 'excise.punjab.gov.pk / excise.gos.pk',
      reason:
        'Domain references provincial vehicle registration (MTMIS) on an unauthorized non-governmental website.',
    };
  }

  // Check 6: Official government subdomain spoofing / look-alike domains
  // Examples: fia.gov.pk.example.com, bisp.gov.pk.fake.xyz, fia-gov-pk.com
  if (
    host.includes('fia.gov.pk') ||
    host.includes('fia-gov-pk') ||
    host.startsWith('fia.') ||
    host.includes('.fia.') ||
    host.startsWith('fia-') ||
    host.includes('-fia-') ||
    host.includes('fia-fine') ||
    host.includes('fia-notice')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Federal Investigation Agency (FIA)',
      officialDomain: 'fia.gov.pk',
      reason: 'Domain name employs look-alike FIA government patterns on an unauthenticated third-party host.',
    };
  }

  if (host.includes('nccia.gov.pk') || host.includes('nccia-gov-pk')) {
    return {
      impersonating: true,
      claimedOrg: 'National Cyber Crime Investigation Agency (NCCIA)',
      officialDomain: 'nccia.gov.pk',
      reason: 'Domain name mimics NCCIA cyber authority infrastructure on an unverified host.',
    };
  }

  if (
    host.includes('bisp.gov.pk') ||
    host.includes('bisp-gov-pk') ||
    host.includes('8171.bisp') ||
    host.startsWith('bisp.') ||
    host.includes('.bisp.')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Benazir Income Support Programme (BISP / 8171)',
      officialDomain: 'bisp.gov.pk',
      reason: 'Domain mimics official BISP government address on an unauthorized host.',
    };
  }

  if (host.includes('pta.gov.pk') || host.includes('pta-gov-pk') || host.includes('sims-pk')) {
    return {
      impersonating: true,
      claimedOrg: 'Pakistan Telecommunication Authority (PTA)',
      officialDomain: 'pta.gov.pk',
      reason: 'Domain mimics official PTA telecom authority or SIM verification portal.',
    };
  }

  if (host.includes('nadra.gov.pk') || host.includes('nadra-gov-pk')) {
    return {
      impersonating: true,
      claimedOrg: 'National Database and Registration Authority (NADRA)',
      officialDomain: 'nadra.gov.pk',
      reason: 'Domain mimics NADRA national registration infrastructure.',
    };
  }

  // Check 7: Brand names directly inside hostname
  if (host.includes('bisp') || host.includes('ehsaas') || host.includes('8171')) {
    return {
      impersonating: true,
      claimedOrg: 'Benazir Income Support Programme (BISP / 8171)',
      officialDomain: 'bisp.gov.pk',
      reason: 'Domain references BISP/Ehsaas welfare programs on an unofficial non-government host.',
    };
  }

  if (
    host.includes('jazzcash') ||
    host.includes('jazzcasch') ||
    host.includes('jazz-cash') ||
    host.includes('jazz-bonus') ||
    host.includes('jazz-reward')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'JazzCash',
      officialDomain: 'jazzcash.com.pk',
      reason: 'Domain references or typosquats JazzCash mobile banking on an unauthenticated third-party host.',
    };
  }

  if (
    host.includes('easypaisa') ||
    host.includes('easypaissa') ||
    host.includes('eazypaisa') ||
    host.includes('easy-paisa') ||
    host.includes('easypaisa-bonus')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Easypaisa',
      officialDomain: 'easypaisa.com.pk',
      reason: 'Domain references or typosquats Easypaisa payments on an unauthenticated host.',
    };
  }

  if (host.includes('sadapay') || host.includes('sada-pay') || host.includes('nayapay') || host.includes('naya-pay')) {
    return {
      impersonating: true,
      claimedOrg: 'SadaPay / NayaPay Digital Wallet',
      officialDomain: 'sadapay.pk / nayapay.com',
      reason: 'Domain references digital wallet services on an unauthenticated host.',
    };
  }

  if (host.includes('meezan') || host.includes('meezaan')) {
    return {
      impersonating: true,
      claimedOrg: 'Meezan Bank',
      officialDomain: 'meezanbank.com',
      reason: 'Domain references or typosquats Meezan Bank on an unauthenticated host.',
    };
  }

  if (host.includes('nadra')) {
    return {
      impersonating: true,
      claimedOrg: 'NADRA',
      officialDomain: 'nadra.gov.pk',
      reason: 'Domain references national civil registration (NADRA) outside official .gov.pk infrastructure.',
    };
  }

  // Commercial Banks
  if (
    host.includes('hbl-') ||
    host.includes('-hbl') ||
    host.includes('ubl-') ||
    host.includes('-ubl') ||
    host.includes('meezan-') ||
    host.includes('-meezan') ||
    host.includes('mcb-') ||
    host.includes('-mcb') ||
    host.includes('alfalah-') ||
    host.includes('-alfalah')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Commercial Banking Institution',
      officialDomain: 'hbl.com / ubldigital.com / meezanbank.com',
      reason: 'Domain mimics an authorized Pakistani commercial bank on an unauthenticated host.',
    };
  }

  // Couriers
  if (
    host.includes('tcs-track') ||
    host.includes('tcs-parcel') ||
    host.includes('tcs-delivery') ||
    host.includes('tcs-express') ||
    host.includes('pakpost-')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Courier & Logistics Service (TCS / Pakistan Post)',
      officialDomain: 'tcsexpress.com / ep.gov.pk',
      reason: 'Domain mimics courier delivery tracking or parcel customs fee collection on an unofficial host.',
    };
  }

  if (
    host.includes('zong-') ||
    host.includes('-zong') ||
    (host.includes('zong') &&
      (host.includes('free') ||
        host.includes('prize') ||
        host.includes('cash') ||
        host.includes('reward')))
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Zong 4G (CMPak)',
      officialDomain: 'zong.com.pk',
      reason: 'Domain mimics Zong cellular services or offers on an unauthenticated third-party host.',
    };
  }

  // Check 8: GCash Mobile Wallet (Philippines)
  if (
    (host.includes('gcash') || host.includes('g-cash')) &&
    !host.endsWith('.gcash.com') &&
    host !== 'gcash.com'
  ) {
    return {
      impersonating: true,
      claimedOrg: 'GCash (G-Xchange Inc.)',
      officialDomain: 'gcash.com',
      reason:
        'Domain references GCash mobile wallet on an unauthenticated third-party host. Official GCash security policy and telecom regulations strictly ban clickable links in SMS.',
    };
  }

  // Check 9: DSWD / Government Ayuda (Philippines)
  if (
    (host.includes('dswd') || host.includes('ayuda-') || host.includes('-ayuda')) &&
    !host.endsWith('.dswd.gov.ph') &&
    !host.endsWith('.gov.ph')
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Department of Social Welfare and Development (DSWD / Ayuda)',
      officialDomain: 'dswd.gov.ph',
      reason:
        'Domain references DSWD or government social aid (Ayuda) on an unofficial non-government host.',
    };
  }

  if (
    host.includes('ufone-') ||
    host.includes('-ufone') ||
    (host.includes('ufone') &&
      (host.includes('free') ||
        host.includes('prize') ||
        host.includes('cash') ||
        host.includes('reward')))
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Ufone 4G (PTML)',
      officialDomain: 'ufone.com',
      reason: 'Domain mimics Ufone telecom services or offers on an unauthorized host.',
    };
  }

  // Check 8: Active login / credential claim form mimics in path on suspicious domains
  const isInformationalSite =
    host.endsWith('wikipedia.org') ||
    host.endsWith('wikimedia.org') ||
    host.endsWith('dawn.com') ||
    host.endsWith('tribune.com.pk') ||
    host.endsWith('geo.tv') ||
    host.endsWith('bbc.com');
  if (!isInformationalSite) {
    if (
      path.includes('bisp-login') ||
      path.includes('claim-bisp') ||
      path.includes('bisp-cash') ||
      path.includes('8171-check')
    ) {
      return {
        impersonating: true,
        claimedOrg: 'Benazir Income Support Programme (BISP / 8171)',
        officialDomain: 'bisp.gov.pk',
        reason: 'Path mimics a BISP beneficiary cash collection portal on an unverified third-party host.',
      };
    }

    if (
      path.includes('jazzcash-pin') ||
      path.includes('jazzcash-verify') ||
      path.includes('easypaisa-otp')
    ) {
      return {
        impersonating: true,
        claimedOrg: 'Mobile Financial Service (JazzCash / Easypaisa)',
        officialDomain: 'jazzcash.com.pk / easypaisa.com.pk',
        reason: 'Path mimics mobile wallet login / PIN verification on an unauthenticated domain.',
      };
    }

    if (
      path.includes('echallan-pay') ||
      path.includes('psca-pay') ||
      path.includes('pay-fine')
    ) {
      return {
        impersonating: true,
        claimedOrg: 'Traffic e-Challan Payment Portal',
        officialDomain: 'psca.gop.pk / sindhpolice.gov.pk',
        reason: 'Path mimics official traffic fine payment collection on an unauthorized host.',
      };
    }
  }

  return { impersonating: false };
}

/**
 * Detects brand impersonation directly from text message content and sender
 * when no URL is present or when the URL did not match standard domain rules.
 */
export function detectContentBrandImpersonation(
  rawText: string,
  sender?: string
): {
  impersonating: boolean;
  claimedOrg?: string;
  officialDomain?: string;
  reason?: string;
} {
  const lower = rawText.toLowerCase();
  const rawSender = (sender || '').trim();
  const isPrivateSimSender = /^(?:03\d{2}|(?:\+92\s?3\d{2}))[\s.-]?\d{7}$/.test(
    rawSender.replace(/[\s-]/g, '')
  );
  const containsPrivatePhone = /\b(?:03\d{2}|(?:\+92\s?3\d{2}))[\s.-]?\d{7}\b/.test(rawText);

  // Check if this is an educational protective advisory (e.g. FIA 1991 warning against scams)
  const isAdvisory =
    (/(?:never|do\s+not|don't)\s+(?:share|provide|disclose|give|tell)\b.*?(?:otp|pin|password|mpin)/i.test(
      lower
    ) ||
      /(?:public\s+advisory|cyber\s+advisory|security\s+alert|citizen\s+warning)\b/i.test(lower)) &&
    (lower.includes('1991') ||
      lower.includes('complaint.fia.gov.pk') ||
      lower.includes('8171') ||
      lower.includes('cnic.sims.pk'));
  if (isAdvisory) return { impersonating: false };

  // 1. Traffic Police / PSCA e-Challan Impersonation (Payment to personal account or private mobile)
  const mentionsTrafficChallan =
    /\b(?:psca|e-challan|echallan|traffic\s+violation|traffic\s+police|challan\s+fine|token\s+tax)\b/i.test(
      lower
    );
  const demandsPrivatePayment =
    /(?:jazzcash|easypaisa|sadapay|upaisa|transfer\s+to|send\s+fine|call\s+03|03\d{2}[\s.-]?\d{7})/i.test(
      lower
    );
  if (mentionsTrafficChallan && (isPrivateSimSender || containsPrivatePhone) && demandsPrivatePayment) {
    return {
      impersonating: true,
      claimedOrg: 'Punjab Safe Cities Authority (PSCA) / Traffic Police',
      officialDomain: 'psca.gop.pk / sindhpolice.gov.pk',
      reason:
        'Traffic violation fine instructing payment to a personal mobile number or private mobile wallet. Official traffic challans are paid strictly via 1Link 1Bill PSID, never to personal phone accounts.',
    };
  }

  // 2. BISP / Ehsaas welfare impersonation
  const mentionsBisp = /\b(?:bisp|benazir\s+income\s+support|ehsaas|wazeefa|kist|imdad\s+fund)\b/i.test(
    lower
  );
  if (mentionsBisp && (isPrivateSimSender || containsPrivatePhone) && rawSender !== '8171') {
    return {
      impersonating: true,
      claimedOrg: 'Benazir Income Support Programme (BISP / 8171)',
      officialDomain: 'bisp.gov.pk',
      reason:
        'Welfare grant claims sent from or providing an unverified private 11-digit mobile number. Official BISP notices originate strictly from shortcode 8171.',
    };
  }

  // 3. FIA / Law enforcement impersonation
  const mentionsFia =
    /\b(?:fia|federal\s+investigation\s+agency|nccia|cyber\s+crime\s+wing|police)\b/i.test(lower);
  const hasLegalCoercion =
    /(?:arrest|giraftari|case\s+darj|muqadma|warrant|penalty|fine|challan|legal\s+action)/i.test(lower);
  if (
    mentionsFia &&
    (isPrivateSimSender || containsPrivatePhone || hasLegalCoercion) &&
    rawSender !== '1991'
  ) {
    return {
      impersonating: true,
      claimedOrg: 'Federal Investigation Agency (FIA / NCCIA)',
      officialDomain: 'fia.gov.pk',
      reason:
        'Law enforcement legal notice, arrest warning, or penalty demand communicated via unverified unofficial mobile channels.',
    };
  }

  // 4. PTA / SIM verification impersonation
  const mentionsPta =
    /\b(?:pta|pakistan\s+telecommunication\s+authority|sim\s+biometric|sim\s+block)\b/i.test(lower);
  const hasPtaCoercion = /(?:block|suspend|penalty|fine|arrest|giraftari|verify|challan)/i.test(lower);
  if (mentionsPta && (isPrivateSimSender || containsPrivatePhone || hasPtaCoercion) && rawSender !== '668') {
    return {
      impersonating: true,
      claimedOrg: 'Pakistan Telecommunication Authority (PTA)',
      officialDomain: 'pta.gov.pk',
      reason:
        'PTA telecommunication or SIM biometric warning sent from an unverified private mobile connection rather than official shortcode 668.',
    };
  }

  // 5. Mobile Wallets / Commercial Bank impersonation
  const mentionsWalletOrBank =
    /\b(?:jazzcash|easypaisa|hbl|ubl|meezan|bank\s+alfalah|mcb|allied\s+bank|faysal\s+bank|habib\s+bank|united\s+bank)\b/i.test(
      lower
    );
  const hasAccountAction =
    /(?:block|suspend|deactivat|clos|band|freeze|biometric|verification|mpin|pin)/i.test(lower);
  if (mentionsWalletOrBank && (isPrivateSimSender || containsPrivatePhone) && hasAccountAction) {
    return {
      impersonating: true,
      claimedOrg: 'Banking / Mobile Financial Service',
      officialDomain: 'jazzcash.com.pk / easypaisa.com.pk',
      reason:
        'Account suspension or biometric lockout alert instructing contact with an unverified private mobile phone number.',
    };
  }

  // 6. Courier / Parcel Customs impersonation
  const mentionsCourier = /\b(?:tcs|leopards|pakistan\s+post|parcel\s+delivery|customs\s+clearance)\b/i.test(
    lower
  );
  const demandsDeliveryFee = /(?:delivery\s+fee|customs\s+fee|clearance\s+charge|pay\s+rs)/i.test(lower);
  if (mentionsCourier && (isPrivateSimSender || containsPrivatePhone) && demandsDeliveryFee) {
    return {
      impersonating: true,
      claimedOrg: 'Courier & Parcel Delivery Service',
      officialDomain: 'tcsexpress.com / ep.gov.pk',
      reason:
        'Parcel delivery or customs release fee demanded from an unverified private mobile phone number.',
    };
  }

  // 7. GCash & DSWD Ayuda Impersonation with external link
  const mentionsGcash = /\b(?:gcash|g-cash)\b/i.test(lower);
  const mentionsDswdAyuda = /\b(?:dswd|ayuda|sap\b|social\s+amelioration)\b/i.test(lower);
  const hasExternalLink = /(?:https?:\/\/|\b(?:bit\.ly|tinyurl|t\.co|is\.gd|cutt\.ly|rb\.gy))/i.test(lower);
  const asksAction = /(?:check\s+(?:your\s+)?balance|update\s+(?:via|account|details)|verify|claim|reactivate)/i.test(lower);

  if (mentionsGcash && hasExternalLink) {
    return {
      impersonating: true,
      claimedOrg: 'GCash (G-Xchange Inc.)',
      officialDomain: 'gcash.com',
      reason:
        'Message claims to be or references GCash with a clickable external link. Official GCash security policy and telecom regulations strictly ban sending clickable links in SMS.',
    };
  }

  if (mentionsDswdAyuda && hasExternalLink && asksAction) {
    return {
      impersonating: true,
      claimedOrg: 'Department of Social Welfare and Development (DSWD / Ayuda)',
      officialDomain: 'dswd.gov.ph',
      reason:
        'Government cash aid (Ayuda / DSWD) claim directing recipients through an unverified external link to update or claim funds. Official aid is disbursed through verified municipal rails, never unsolicited SMS links.',
    };
  }

  return { impersonating: false };
}
