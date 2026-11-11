import { app } from '../server.ts';
import type { Request, Response } from 'express';

export default function handler(req: Request, res: Response) {
  if (req.url === '/' || !req.url) {
    req.url = '/api/check-link';
  }
  return app(req, res);
}
