/* eslint-disable no-underscore-dangle */
<<<<<<< Updated upstream
/* eslint-disable @typescript-eslint/camelcase */
import Secp256k1 from 'secp256k1';

=======
>>>>>>> Stashed changes
import {
  blobFromHex,
  blobFromUint8Array,
  blobToHex,
  BinaryBlob,
  blobFromBuffer,
} from '@dfinity/candid';
<<<<<<< Updated upstream
import {
  HttpAgentRequest,
  PublicKey,
  requestIdOf,
  SignIdentity,
} from '@dfinity/agent';
=======
import { PublicKey, SignIdentity } from '@dfinity/agent';
import * as Secp256k1 from 'noble-secp256k1';
>>>>>>> Stashed changes
import Secp256k1PublicKey from './publicKey';

declare type PublicKeyHex = string;
declare type SecretKeyHex = string;
export declare type JsonableSecp256k1Identity = [PublicKeyHex, SecretKeyHex];

class Secp256k1KeyIdentity extends SignIdentity {
  public static fromParsedJson(obj: [string, string]): Secp256k1KeyIdentity {
    const [publicKeyRaw, privateKeyRaw] = obj;
    return new Secp256k1KeyIdentity(
      Secp256k1PublicKey.fromRaw(blobFromHex(publicKeyRaw)),
      blobFromHex(privateKeyRaw)
    );
  }

  public static fromJSON(json: string): Secp256k1KeyIdentity {
    const parsed = JSON.parse(json);
    if (Array.isArray(parsed)) {
      if (typeof parsed[0] === 'string' && typeof parsed[1] === 'string') {
        return this.fromParsedJson([parsed[0], parsed[1]]);
      }
      throw new Error(
        'Deserialization error: JSON must have at least 2 items.'
      );
    } else if (typeof parsed === 'object' && parsed !== null) {
      const { publicKey, _publicKey, secretKey, _privateKey } = parsed;
      const pk = publicKey
        ? Secp256k1PublicKey.fromRaw(
            blobFromUint8Array(new Uint8Array(publicKey.data))
          )
        : Secp256k1PublicKey.fromDer(
            blobFromUint8Array(new Uint8Array(_publicKey.data))
          );

      if (publicKey && secretKey && secretKey.data) {
        return new Secp256k1KeyIdentity(
          pk,
          blobFromUint8Array(new Uint8Array(secretKey.data))
        );
      }
      if (_publicKey && _privateKey && _privateKey.data) {
        return new Secp256k1KeyIdentity(
          pk,
          blobFromUint8Array(new Uint8Array(_privateKey.data))
        );
      }
    }
    throw new Error(
      `Deserialization error: Invalid JSON type for string: ${JSON.stringify(
        json
      )}`
    );
  }

  public static fromKeyPair(
    publicKey: BinaryBlob,
    privateKey: BinaryBlob
  ): Secp256k1KeyIdentity {
    return new Secp256k1KeyIdentity(
      Secp256k1PublicKey.fromRaw(publicKey),
      privateKey
    );
  }

  public static fromSecretKey(secretKey: ArrayBuffer): Secp256k1KeyIdentity {
    const publicKey = Secp256k1.getPublicKey(new Uint8Array(secretKey), false);
    const identity = Secp256k1KeyIdentity.fromKeyPair(
      blobFromUint8Array(publicKey),
      blobFromUint8Array(new Uint8Array(secretKey))
    );
    return identity;
  }

  protected _publicKey: Secp256k1PublicKey;

  // `fromRaw` and `fromDer` should be used for instantiation, not this constructor.
  protected constructor(
    publicKey: PublicKey,
    protected _privateKey: BinaryBlob
  ) {
    super();
    this._publicKey = Secp256k1PublicKey.from(publicKey);
  }

  /**
   * Serialize this key to JSON.
   */
  public toJSON(): JsonableSecp256k1Identity {
    return [blobToHex(this._publicKey.toRaw()), blobToHex(this._privateKey)];
  }

  /**
   * Return a copy of the key pair.
   */
  public getKeyPair(): {
    secretKey: BinaryBlob;
    publicKey: Secp256k1PublicKey;
  } {
    return {
      secretKey: blobFromUint8Array(new Uint8Array(this._privateKey)),
      publicKey: this._publicKey,
    };
  }

  /**
   * Return the public key.
   */
  public getPublicKey(): PublicKey {
    return this._publicKey;
  }

  /**
   * Signs a blob of data, with this identity's private key.
   * @param challenge - challenge to sign with this identity's secretKey, producing a signature
   */
  public async sign(challenge: BinaryBlob): Promise<BinaryBlob> {
    // if message is shorter than 32, must pad it.
    // if longer, must do something weird
    console.log('challenge length', challenge.length);
    const padding = Buffer.alloc(challenge.length % 2);
    const message = new Uint8Array([...padding, ...challenge]);
    const signature = await Secp256k1.sign(message, this._privateKey);
    return blobFromUint8Array(signature);
  }

  /**
   * Transform a request into a signed version of the request. This is done last
   * after the transforms on the body of a request. The returned object can be
   * anything, but must be serializable to CBOR.
   * @param request - internet computer request to transform
   */
  public async transformRequest(request: HttpAgentRequest): Promise<unknown> {
    const { body, ...fields } = request;
    const requestId = await requestIdOf(body);
    const domainSeparator = Buffer.from(
      new TextEncoder().encode('\x0Aic-request')
    );
    return {
      ...fields,
      body: {
        content: body,
        sender_pubkey: this.getPublicKey().toDer(),
        sender_sig: await this.sign(
          blobFromBuffer((Buffer as any).concat([domainSeparator, requestId]))
        ),
      },
    };
  }
}

export default Secp256k1KeyIdentity;
