import createHmac from 'create-hmac';

const ED25519_CURVE = 'Bitcoin seed';
const btcecS256N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
);

export default class ExtendedKey {
  private key: Buffer;

  private chainCode: Buffer;

  private pubKey: Buffer | undefined;

  constructor(key: Buffer, chainCode: Buffer, pubkey?: Buffer) {
    this.key = key;
    this.chainCode = chainCode;
    this.pubKey = pubkey;
  }

  public static newMasterKey(seed: Buffer): ExtendedKey {
    const hmac = createHmac('sha512', ED25519_CURVE);
    const I = hmac.update(seed).digest();

    const secretKey = I.slice(0, 32);
    const chainCode = I.slice(32);

    return new ExtendedKey(secretKey, chainCode);
  }

  public derive(i: number): any {
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(i, 0);

    const data = Buffer.concat([Buffer.alloc(1, 0), this.key, indexBuffer]);

    const I = createHmac('sha512', this.chainCode)
      .update(data)
      .digest() as Buffer;

    const Il = I.slice(0, 32);
    const childChainCode = I.slice(32);

    /// this part is not on RockyDerive but it is on keysmith
    // let ilNum = BigInt(Il.readUInt32BE());
    // const keyNum = BigInt(this.key.readUInt32BE());
    // ilNum += keyNum;
    // ilNum %= btcecS256N;
    // const childKey = Buffer.allocUnsafe(32);
    // childKey.writeBigUInt64BE(ilNum, 0);

    // this.key = childKey;
    this.key = Il;
    this.chainCode = childChainCode;
  }

  public secretKey(): Buffer {
    return Buffer.concat([this.key, this.chainCode]);
  }

  public publicKey(): Buffer {
    return this.chainCode;
  }
}
