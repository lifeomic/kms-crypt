import { encrypt, decrypt, encryptObject, decryptObject } from "./index";

import { EncryptRequest, EncryptObjectRequest, Encrypted } from "./types";

let mockKMS: any;

jest.mock('aws-sdk', () => {
  return {
    KMS: jest.fn().mockImplementation(() => {
      return mockKMS;
    })
  }
})

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

beforeEach(() => {
  jest.clearAllMocks();
});

test("should be able to encrypt data", async () => {
  const keyCiphertext = Buffer.from("hello");

  const generateDataKeyStub = jest.fn().mockResolvedValue({
    CiphertextBlob: keyCiphertext,
    Plaintext: Buffer.from("world"),
  });

  mockKMS = {
    generateDataKey: createAwsPromiseReturnStub(generateDataKeyStub),
  };

  const encrypted = await encrypt(
    {
      algorithm: "aes256",
      kmsKeyId: "abc",
      data: Buffer.from(JSON.stringify({ a: "b" })),
    } as EncryptRequest,
  );

  expect(encrypted).toEqual({
    algorithm: "aes256",
    keyCiphertext,
    dataCiphertext: validDataCipherText,
  } as Encrypted);
});

test("should be able to encrypt an object", async () => {
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
    } as EncryptObjectRequest,
  );

  expect(encrypted).toEqual({
    algorithm: "aes256",
    keyCiphertext,
    dataCiphertext: validDataCipherText,
  } as Encrypted);
});

test("should be able to decrypt to a buffer", async () => {
  const keyCiphertext = Buffer.from("hello");

  const decryptStub = jest.fn().mockResolvedValue({
    Plaintext: Buffer.from("world"),
  });

  mockKMS = {
    decrypt: createAwsPromiseReturnStub(decryptStub),
  };

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

  const decryptStub = jest.fn().mockResolvedValue({
    Plaintext: Buffer.from("world"),
  });

  mockKMS = {
    decrypt: createAwsPromiseReturnStub(decryptStub),
  };

  const decrypted = await decryptObject({
    algorithm: "aes256",
    keyCiphertext,
    dataCiphertext: validDataCipherText,
  });

  expect(decrypted).toEqual({
    a: "b",
  });
});
