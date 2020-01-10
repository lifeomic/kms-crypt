import * as crypto from 'crypto';

export function pbkdf2Async(
  password: crypto.BinaryLike,
  initializationVector: Buffer
) {
  return new Promise<Buffer>((resolve, reject) => {
    crypto.pbkdf2(
      password,
      initializationVector.toString(),
      10000,
      32,
      'sha512',
      (err, res) => {
        return err ? reject(err) : resolve(res);
      });
  });
}
