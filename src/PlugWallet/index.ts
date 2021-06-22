import { Ed25519KeyIdentity } from '@dfinity/identity';
import {
  createAccountFromMnemonic,
  createAccountFromImported,
} from '../utils/account';

interface PlugWalletArgs {
  name?: string;
  walletNumber: number;
  mnemonic: string;
  identity?: string[];
  accountId?: string;
}

class PlugWallet {
  name: string;
  walletNumber: number;
  accountId: string;
  private _identity: Ed25519KeyIdentity;

  constructor({
    name,
    walletNumber,
    mnemonic,
    ...importedArgs
  }: PlugWalletArgs) {
    this.name = name || 'Main IC Wallet';
    this.walletNumber = walletNumber;

    const { identity, accountId } =
      importedArgs.identity && importedArgs.accountId
        ? createAccountFromImported(
            mnemonic,
            importedArgs.identity,
            importedArgs.accountId
          )
        : createAccountFromMnemonic(mnemonic, walletNumber);
    this._identity = identity;
    this.accountId = accountId;
  }

  get keys() {
    return this._identity.getKeyPair();
  }

  get principal() {
    return this._identity.getPrincipal();
  }

  set setName(val: string) {
    this.name = val;
  }

  public toJSON = () => ({
    name: this.name,
    walletNumber: this.walletNumber,
    identity: this._identity.toJSON(),
    accountId: this.accountId,
  });
}

export default PlugWallet;
