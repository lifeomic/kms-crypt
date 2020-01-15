import { KMS } from "aws-sdk";
import * as crypto from "crypto";
import { Encrypted, EncryptedWithIv, EncryptObjectRequest, EncryptRequest } from "./types";

export * from './types';

interface DecryptUsingTargetedDecipherMethodParams {
  algorithm: string;
  password: string;
  dataCiphertext: Buffer;
  iv?: Buffer;
}

interface DecryptParams extends Encrypted {
  iv?: Buffer;
}

interface GenerateDataKeyResponse {
  keyCiphertext: Buffer;
  password: string;
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
  const { algorithm, password, dataCiphertext, iv } = params;
  let decipher: crypto.Decipher;

  if (iv) {
    decipher = crypto.createDecipheriv(algorithm, password, iv);
  } else {
    decipher = crypto.createDecipher(algorithm, password);
  }

  return Buffer.concat([
    decipher.update(dataCiphertext),
    decipher.final()
  ]);
}

function getDataCipherTextFromCipher (
  cipher: crypto.Cipher,
  encryptRequest: EncryptRequest
) {
  return Buffer.concat([
    cipher.update(encryptRequest.data),
    cipher.final(),
  ]);
}

async function generateDataKey (
  encryptRequest: EncryptRequest,
  config?: KMS.Types.ClientConfiguration,
): Promise<GenerateDataKeyResponse> {
  const kms = new KMS(config);

  const dataKeyResponse = await kms
    .generateDataKey({
      KeyId: encryptRequest.kmsKeyId,
      KeySpec: "AES_256",
    })
    .promise();

  const keyCiphertext = dataKeyResponse.CiphertextBlob as Buffer;
  const password = dataKeyResponse.Plaintext as string;

  return {
    keyCiphertext,
    password
  };
}

/**
 * Encrypts data using a KMS data encryption key
 * @param kms
 * @param encryptRequest
 */
export async function encrypt(
  encryptRequest: EncryptRequest,
  config?: KMS.Types.ClientConfiguration,
): Promise<EncryptedWithIv> {
  const { algorithm } = encryptRequest;
  const { keyCiphertext, password }= await generateDataKey(encryptRequest, config);

  const iv = crypto.randomBytes(INITIALIZATION_VECTOR_SIZE);
  const cipher = crypto.createCipheriv(algorithm, password, iv);
  const dataCiphertext = getDataCipherTextFromCipher(cipher, encryptRequest);

  return {
    algorithm,
    keyCiphertext,
    dataCiphertext,
    iv
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
  encrypted: DecryptParams,
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
    password,
    iv: encrypted.iv
  });
}

/**
 * Decrypts an object using KMS
 * @param kms
 * @param encrypted
 */
export async function decryptObject<T = any>(
  encrypted: DecryptParams,
  config?: KMS.Types.ClientConfiguration,
) {
  const decrypted = await decrypt(encrypted, config);
  return JSON.parse(decrypted.toString("utf8")) as T;
}
