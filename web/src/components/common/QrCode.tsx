import { useMemo } from 'react';
import { encode } from 'uqr';

interface Props {
  value: string;
  size?: number;
  label?: string;
}

/**
 * QR code rendered as an SVG path built in React (no innerHTML). Always
 * dark-on-white so authenticator apps can scan it in dark mode too.
 */
export function QrCode({ value, size = 192, label = 'QR code' }: Props) {
  const { path, dim } = useMemo(() => {
    const qr = encode(value, { ecc: 'M', border: 4 });
    let d = '';
    qr.data.forEach((row, y) => {
      row.forEach((on, x) => {
        if (on) d += `M${x} ${y}h1v1h-1z`;
      });
    });
    return { path: d, dim: qr.size };
  }, [value]);

  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      shapeRendering="crispEdges"
      className="rounded-md border bg-white"
    >
      <rect width={dim} height={dim} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  );
}
