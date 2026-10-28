import { PNG } from 'pngjs';
import jsQR from 'jsqr';
import jpeg from 'jpeg-js';

export interface QrDecodeResult {
  attempted: boolean;
  detected: boolean;
  decodedValue: string | null;
  errorMessage?: string;
}

/**
 * Safely decodes a QR code from a raw image buffer (PNG, JPEG) in pure JavaScript.
 * Operates strictly offline without external network calls or third-party APIs.
 */
export async function decodeQrFromImageBuffer(
  buffer: Buffer,
  mimeType: string
): Promise<QrDecodeResult> {
  try {
    let width = 0;
    let height = 0;
    let data: Uint8Array | Uint8ClampedArray | null = null;

    // Check PNG signature: 89 50 4E 47
    const isPng =
      mimeType.includes('png') ||
      (buffer.length >= 4 &&
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47);

    // Check JPEG signature: FF D8 FF
    const isJpeg =
      mimeType.includes('jpeg') ||
      mimeType.includes('jpg') ||
      (buffer.length >= 3 &&
        buffer[0] === 0xff &&
        buffer[1] === 0xd8 &&
        buffer[2] === 0xff);

    if (isPng) {
      try {
        const png = PNG.sync.read(buffer);
        width = png.width;
        height = png.height;
        data = png.data;
      } catch (pngErr: any) {
        // Fall back to attempting JPEG if header mismatched
        try {
          const rawJpeg = jpeg.decode(buffer, { useTArray: true });
          width = rawJpeg.width;
          height = rawJpeg.height;
          data = rawJpeg.data;
        } catch {
          return {
            attempted: true,
            detected: false,
            decodedValue: null,
            errorMessage: `PNG parsing error: ${pngErr.message}`,
          };
        }
      }
    } else if (isJpeg) {
      try {
        const rawJpeg = jpeg.decode(buffer, { useTArray: true });
        width = rawJpeg.width;
        height = rawJpeg.height;
        data = rawJpeg.data;
      } catch (jpegErr: any) {
        return {
          attempted: true,
          detected: false,
          decodedValue: null,
          errorMessage: `JPEG parsing error: ${jpegErr.message}`,
        };
      }
    } else {
      // Try PNG first, then JPEG
      try {
        const png = PNG.sync.read(buffer);
        width = png.width;
        height = png.height;
        data = png.data;
      } catch {
        try {
          const rawJpeg = jpeg.decode(buffer, { useTArray: true });
          width = rawJpeg.width;
          height = rawJpeg.height;
          data = rawJpeg.data;
        } catch {
          return {
            attempted: false,
            detected: false,
            decodedValue: null,
            errorMessage: 'Unsupported image format for offline QR decoding (supports PNG, JPEG).',
          };
        }
      }
    }

    if (!data || width === 0 || height === 0) {
      return {
        attempted: true,
        detected: false,
        decodedValue: null,
        errorMessage: 'Could not extract pixel matrix from image buffer.',
      };
    }

    // Convert to Uint8ClampedArray for jsQR
    const clamped = new Uint8ClampedArray(data);
    const code = jsQR(clamped, width, height, {
      inversionAttempts: 'attemptBoth',
    });

    if (code && code.data) {
      return {
        attempted: true,
        detected: true,
        decodedValue: code.data.trim(),
      };
    }

    return {
      attempted: true,
      detected: false,
      decodedValue: null,
    };
  } catch (err: any) {
    return {
      attempted: true,
      detected: false,
      decodedValue: null,
      errorMessage: err.message || 'Error occurred during offline QR code decoding.',
    };
  }
}
