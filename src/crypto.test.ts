import * as crypto from 'crypto';
import { pbkdf2Async } from './crypto';

jest.mock('crypto');

beforeEach(() => {
  jest.clearAllMocks();
});

test('should reject if pbkdf2Async rejects', async () => {
  (crypto.pbkdf2 as any).mockImplementationOnce((
    password: crypto.BinaryLike,
    salt: crypto.BinaryLike,
    iterations: number,
    keylen: number,
    digest: string,
    callback: (err: Error | null, derivedKey: Buffer) => any) => {
    callback(new Error('expected error'), Buffer.from(''));
  });

  await expect(
    pbkdf2Async('abc', Buffer.from(''))
  ).rejects.toThrow(
    'expected error'
  );
});
