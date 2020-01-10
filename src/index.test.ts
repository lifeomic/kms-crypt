import * as crypto from 'crypto';
import { decrypt, decryptObject, encrypt, encryptObject} from "./index";
import { Encrypted } from "./types";

let mockKMS: any;

jest.mock('aws-sdk', () => {
  return {
    KMS: jest.fn().mockImplementation(() => {
      return mockKMS;
    })
  }
});

// Data cipher text that resolves to: { a: 'b' }
const validDataCipherText = Buffer.from([
  92,
  102,
  94,
  9,
  202,
  229,
  218,
  74,
  196,
  164,
  171,
  84,
  148,
  206,
  128,
  111,
]);

function createAwsPromiseReturnStub(promiseStub: any) {
  return jest.fn().mockReturnValue({
    promise: promiseStub,
  });
}

function initializeMockKmsDecrypt (plainTextKey: string | Buffer) {
  const decryptStub = jest.fn().mockResolvedValue({
    Plaintext: plainTextKey
  });

  mockKMS = {
    decrypt: createAwsPromiseReturnStub(decryptStub),
  };

  return mockKMS;
}

function getKeyCipherText () {
  return crypto.randomBytes(32 / 2).toString('hex');
}

beforeEach(() => {
  jest.clearAllMocks();
});

test("should be able to encrypt data and decrypt the same data", async () => {
  const keyCiphertext = getKeyCipherText();

  const generateDataKeyStub = jest.fn().mockResolvedValue({
    CiphertextBlob: keyCiphertext,
    Plaintext: keyCiphertext,
  });

  mockKMS = {
    generateDataKey: createAwsPromiseReturnStub(generateDataKeyStub),
  };

  const encrypted = await encrypt(
    {
      algorithm: "aes256",
      kmsKeyId: "abc",
      data: Buffer.from(JSON.stringify({ a: "b" })),
    }
  );

  const expectedEncryptedResult: Encrypted = {
    algorithm: "aes256",
    keyCiphertext: keyCiphertext as unknown as Buffer,
    dataCiphertext: expect.any(Buffer),
  };

  expect(encrypted).toEqual(expectedEncryptedResult);
  initializeMockKmsDecrypt(keyCiphertext);

  const decrypted = await decryptObject({
    algorithm: "aes256",
    keyCiphertext: encrypted.keyCiphertext,
    dataCiphertext: encrypted.dataCiphertext,
  });

  expect(decrypted).toEqual({
    a: "b",
  })
});

test("should be able to encrypt an object and decrypt the same object", async () => {
  const keyCiphertext = Buffer.from("hello");

  const generateDataKeyStub = jest.fn().mockResolvedValue({
    CiphertextBlob: keyCiphertext,
    Plaintext: Buffer.from("world"),
  });

  mockKMS = {
    generateDataKey: createAwsPromiseReturnStub(generateDataKeyStub),
  };

  const encrypted = await encryptObject(
    {
      algorithm: "aes256",
      kmsKeyId: "abc",
      data: {
        a: "b",
      },
    }
  );

  const expectedEncryptedResult: Encrypted = {
    algorithm: "aes256",
    keyCiphertext,
    dataCiphertext: expect.any(Buffer),
  };

  expect(encrypted).toEqual(expectedEncryptedResult);
});

test("should be able to decrypt to a buffer", async () => {
  const keyCiphertext = Buffer.from("hello");
  initializeMockKmsDecrypt(Buffer.from("world"));

  const decrypted = await decrypt({
    algorithm: "aes256",
    keyCiphertext,
    dataCiphertext: validDataCipherText,
  });

  expect(Buffer.isBuffer(decrypted)).toBe(true);
  expect(JSON.parse(decrypted.toString("utf8"))).toEqual({
    a: "b",
  });
});

test("should be able to decrypt an object", async () => {
  const keyCiphertext = Buffer.from("hello");
  initializeMockKmsDecrypt(Buffer.from("world"));

  const decrypted = await decryptObject({
    algorithm: "aes256",
    keyCiphertext,
    dataCiphertext: validDataCipherText,
  });

  expect(decrypted).toEqual({
    a: "b",
  });
});
