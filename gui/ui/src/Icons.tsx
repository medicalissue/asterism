import type {SVGProps} from 'react';

type Props = SVGProps<SVGSVGElement>;

function Icon({children, ...props}: Props) {
  return (
    <svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" {...props}>
      {children}
    </svg>
  );
}

export const InstancesIcon = (props: Props) => (
  <Icon {...props}><rect x="2" y="2.5" width="12" height="4" rx="1.4"/><rect x="2" y="9.5" width="12" height="4" rx="1.4"/><path d="M4.5 4.5h.01M4.5 11.5h.01"/></Icon>
);
export const DevicesIcon = (props: Props) => (
  <Icon {...props}><rect x="2" y="3" width="8" height="9" rx="1.5"/><path d="M10 6h2.2c1 0 1.8.8 1.8 1.8V12M4.5 14h7"/></Icon>
);
export const VolumesIcon = (props: Props) => (
  <Icon {...props}><ellipse cx="8" cy="3.5" rx="5.5" ry="2"/><path d="M2.5 3.5v4c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2v-4M2.5 7.5v4c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2v-4"/></Icon>
);
export const SettingsIcon = (props: Props) => (
  <Icon {...props}><circle cx="8" cy="8" r="2.2"/><path d="M6.9 2.2h2.2l.5 1.6 1.4.8 1.7-.3 1.1 1.9-1.2 1.2v1.5l1.2 1.2-1.1 1.9-1.7-.3-1.4.8-.5 1.6H6.9l-.5-1.6-1.4-.8-1.7.3-1.1-1.9 1.2-1.2V7.4L2.2 6.2l1.1-1.9 1.7.3 1.4-.8.5-1.6Z"/></Icon>
);
export const PlayIcon = (props: Props) => <Icon {...props}><path d="m5.5 3.5 7 4.5-7 4.5v-9Z"/></Icon>;
export const StopIcon = (props: Props) => <Icon {...props}><rect x="4" y="4" width="8" height="8" rx="1.2"/></Icon>;
export const TerminalIcon = (props: Props) => <Icon {...props}><rect x="2" y="2.5" width="12" height="11" rx="1.5"/><path d="m4.5 6 2 2-2 2M8.5 10h3"/></Icon>;
export const LayersIcon = (props: Props) => <Icon {...props}><path d="m8 2 6 3-6 3-6-3 6-3Z"/><path d="m2 8 6 3 6-3M2 11l6 3 6-3"/></Icon>;
export const LinkIcon = (props: Props) => <Icon {...props}><path d="M6.5 9.5 9.5 6.5M5.7 11.9l-1 .1a2.7 2.7 0 0 1 0-5.4h2M10.3 4.1l1-.1a2.7 2.7 0 0 1 0 5.4h-2"/></Icon>;
export const PlusIcon = (props: Props) => <Icon {...props}><path d="M8 3v10M3 8h10"/></Icon>;
export const RefreshIcon = (props: Props) => <Icon {...props}><path d="M13 6a5 5 0 1 0 .1 3M13 2v4H9"/></Icon>;
export const CloseIcon = (props: Props) => <Icon {...props}><path d="m4 4 8 8M12 4l-8 8"/></Icon>;
export const CopyIcon = (props: Props) => <Icon {...props}><rect x="5" y="5" width="8" height="8" rx="1.5"/><path d="M3 11H2.8A1.8 1.8 0 0 1 1 9.2V2.8A1.8 1.8 0 0 1 2.8 1h6.4A1.8 1.8 0 0 1 11 2.8V3"/></Icon>;
export const ChevronIcon = (props: Props) => <Icon {...props}><path d="m6 3.5 4.5 4.5L6 12.5"/></Icon>;
export const CloudIcon = (props: Props) => <Icon {...props}><path d="M4.2 12.5h7.2a2.6 2.6 0 0 0 .4-5.2A4 4 0 0 0 4.2 6 3.3 3.3 0 0 0 4.2 12.5Z"/></Icon>;
export const BoxIcon = (props: Props) => <Icon {...props}><path d="m8 2 5.5 3v6L8 14l-5.5-3V5L8 2Z"/><path d="m2.5 5 5.5 3 5.5-3M8 8v6"/></Icon>;
export const BackupIcon = (props: Props) => <Icon {...props}><path d="M3 3.5h8l2 2V13H3V3.5Z"/><path d="M5 3.5v3h5v-3M5.5 13V9h5v4"/></Icon>;
