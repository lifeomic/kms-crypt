import { KMS } from "aws-sdk";
import * as crypto from "crypto";
import { pbkdf2Async } from './crypto';
import { Encrypted, EncryptObjectRequest, EncryptRequest } from "./types";

export * from './types';

interface DecryptUsingTargetedDecipherMethodParams {
  algorithm: string;
  password: string;
  dataCiphertext: Buffer
}

const INITIALIZATION_VECTOR_SIZE = 16;

/**
 * Decrypts using `createDecipheriv` or `createDecipher` based on whether we
 * detected an initialization vector. Allows for backwards compatibility in
 * existing encrypted data.
 *
 * @param params {DecryptUsingTargetedDecipherMethodParams}
 */
async function decryptUsingTargetedDecipherMethod (
  params: DecryptUsingTargetedDecipherMethodParams
) {
  const { algorithm, password, dataCiphertext } = params;
  const charIndexAfterInitializationVector = INITIALIZATION_VECTOR_SIZE + 1;

  if (dataCiphertext.slice(INITIALIZATION_VECTOR_SIZE, charIndexAfterInitializationVector).toString() === ':') {
    const initializationVector = dataCiphertext.slice(0, INITIALIZATION_VECTOR_SIZE);

    const toDecipher = await pbkdf2Async(password, initializationVector);
    const decipher = crypto.createDecipheriv(algorithm, toDecipher, initializationVector);

    return Buffer.concat([
      decipher.update(dataCiphertext.slice(charIndexAfterInitializationVector)),
      decipher.final()
    ]);
  } else {
    /* tslint:disable-next-line:deprecation */
    const decipher = crypto.createDecipher(algorithm, password);

    return Buffer.concat([
      decipher.update(dataCiphertext),
      decipher.final()
    ]);
  }
}

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
  const initializationVector = crypto.randomBytes(INITIALIZATION_VECTOR_SIZE);

  const key = await pbkdf2Async(password, initializationVector);
  const cipher = crypto.createCipheriv(algorithm, key, initializationVector);

  const dataCiphertext = Buffer.concat([
    initializationVector,
    Buffer.from(':'),
    cipher.update(Buffer.from(encryptRequest.data)),
    cipher.final()
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

  return decryptUsingTargetedDecipherMethod({
    algorithm: encrypted.algorithm,
    dataCiphertext: encrypted.dataCiphertext,
    password
  });
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
