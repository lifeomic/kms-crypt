import { KMS } from "aws-sdk";
import * as crypto from "crypto";

import { Encrypted, EncryptObjectRequest, EncryptRequest } from "./types";

export * from './types';

/**
 * Encrypts data using a KMS data encryption key
 * @param kms
 * @param encryptRequest
 */
export async function encrypt(
  encryptRequest: EncryptRequest,
  config?: KMS.Types.ClientConfiguration,
): Promise<Encrypted> {
  const kms = new KMS(config);
  const { kmsKeyId, algorithm } = encryptRequest;

  const dataKeyResponse = await kms
    .generateDataKey({
      KeyId: kmsKeyId,
      KeySpec: "AES_256",
    })
    .promise();

  const keyCiphertext = dataKeyResponse.CiphertextBlob as Buffer;
  const password = dataKeyResponse.Plaintext as string;
  /* tslint:disable-next-line:deprecation */
  const cipher = crypto.createCipher(algorithm, password);

  const dataCiphertext = Buffer.concat([
    cipher.update(encryptRequest.data),
    cipher.final(),
  ]);

  return {
    algorithm,
    keyCiphertext,
    dataCiphertext,
  };
}

/**
 * Encrypts an object using a KMS data encryption key
 * @param kms
 * @param encryptRequest
 */
export async function encryptObject(
  encryptRequest: EncryptObjectRequest,
  config?: KMS.Types.ClientConfiguration,
) {
  return encrypt(
    {
      data: Buffer.from(JSON.stringify(encryptRequest.data), "utf8"),
      kmsKeyId: encryptRequest.kmsKeyId,
      algorithm: encryptRequest.algorithm,
    },
    config,
  );
}

/**
 * Decrypts data using KMS key
 * @param kms
 * @param encrypted
 */
export async function decrypt(
  encrypted: Encrypted,
  config?: KMS.Types.ClientConfiguration,
): Promise<Buffer> {
  const kms = new KMS(config);
  const decryptResponse = await kms
    .decrypt({
      CiphertextBlob: encrypted.keyCiphertext,
    })
    .promise();

  const password = decryptResponse.Plaintext as string;

  // We'll be decrypting the data using the password
  /* tslint:disable-next-line:deprecation */
  const decipher = crypto.createDecipher(encrypted.algorithm, password);

  return Buffer.concat([
    decipher.update(encrypted.dataCiphertext),
    decipher.final(),
  ]);
}

/**
 * Decrypts an object using KMS
 * @param kms
 * @param encrypted
 */
export async function decryptObject<T = any>(
  encrypted: Encrypted,
  config?: KMS.Types.ClientConfiguration,
) {
  const decrypted = await decrypt(encrypted, config);
  return JSON.parse(decrypted.toString("utf8")) as T;
}
