import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config/env';

/**
 * Generate a JWT token
 * @param payload - Data to sign in the token
 * @param expiresIn - Expiration time (default: '1h')
 * @returns Signed JWT token
 */
export function generateToken(payload: object, expiresIn: string = '1h'): string {
  return jwt.sign(payload, JWT_SECRET as unknown as string | Buffer, { expiresIn });
}

/**
 * Verify a JWT token
 * @param token - JWT token to verify
 * @returns Decoded payload if valid, throws error otherwise
 */
export function verifyToken(token: string): jwt.JwtPayload {
  return jwt.verify(token, JWT_SECRET as unknown as string | Buffer) as jwt.JwtPayload;
}
