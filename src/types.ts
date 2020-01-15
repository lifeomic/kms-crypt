export interface EncryptRequest {
  data: Buffer;
  kmsKeyId: string;
  algorithm: string;
}

export interface EncryptObjectRequest {
  data: object;
  kmsKeyId: string;
  algorithm: string;
}

export interface Encrypted {
  algorithm: string;
  keyCiphertext: Buffer;
  dataCiphertext: Buffer;
}

export interface EncryptedWithIv extends Encrypted {
  iv: Buffer;
}
