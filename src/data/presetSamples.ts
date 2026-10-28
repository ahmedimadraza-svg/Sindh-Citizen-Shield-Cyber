export interface PresetSample {
  id: string;
  filename: string;
  sender: string;
  senderLabel?: string;
  isOfficialShortcode: boolean;
  messageText: string;
  tag: string;
  badgeType: 'unverified' | 'theft' | 'extortion' | 'official';
  dateLabel: string;
}

export const PRESET_SAMPLES: PresetSample[] = [
  {
    id: 'bisp-sms',
    filename: 'bisp_prize_sms_sample.png',
    sender: '+92 345 8892102',
    senderLabel: 'SMS from: +92 345 8892102',
    isOfficialShortcode: false,
    messageText: 'Congratulations! You won 25,000 cash grant. Share OTP to claim or call 0345-XXXXXXX',
    tag: 'Unverified SMS',
    badgeType: 'unverified',
    dateLabel: 'Today 11:42 AM',
  },
  {
    id: 'jazzcash-alert',
    filename: 'jazzcash_pin_deactivation.png',
    sender: '+92 301 7712399',
    senderLabel: 'SMS from: +92 301 7712399',
    isOfficialShortcode: false,
    messageText: 'Urgent: Your account is scheduled for deactivation. Confirm 4-digit PIN immediately to retain your wallet balance.',
    tag: 'Account Theft Alert',
    badgeType: 'theft',
    dateLabel: 'Yesterday 04:15 PM',
  },
  {
    id: 'blackmail-ransom',
    filename: 'whatsapp_extortion_threat.png',
    sender: '+92 312 9991122',
    senderLabel: 'WhatsApp from: Unknown Sender',
    isOfficialShortcode: false,
    messageText: 'Send ransom to this Easypaisa number or private recording will be broadcasted to your contact list.',
    tag: 'FIA Priority Threat',
    badgeType: 'extortion',
    dateLabel: 'Oct 15, 08:30 PM',
  },
  {
    id: 'official-8171',
    filename: 'official_8171_beneficiary.png',
    sender: '8171',
    senderLabel: 'SMS from: 8171 (Govt of Pakistan)',
    isOfficialShortcode: true,
    messageText: 'Muhtarma, aap Benazir Kafalat Program ki raqam 10,500 rupay qareebi HBL Connect ya biometric center se wasool kar sakti hain.',
    tag: 'Authenticated Civic Notice',
    badgeType: 'official',
    dateLabel: 'Oct 14, 09:00 AM',
  },
];
