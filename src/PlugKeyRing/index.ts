import PlugWallet from '../PlugWallet';
import { createAccount } from '../utils/account';
import Storage from '../utils/storage';
import mockStore from '../utils/storage/mock';

const CryptoJS = require('crypto-js');

interface PlugState {
  wallets: Array<PlugWallet> | string;
  currentWalletId?: number;
  password?: string;
  mnemonic?: string;
}

const store = process.env.NODE_ENV === 'test' ? mockStore : new Storage();

class PlugKeyRing {
  private state: PlugState;

  private isUnlocked = false;

  public loadFromPersistance = async (password: string): Promise<void> => {
    const state = (await store.get()) as PlugState;
    if (state) {
      const decrypted = this.decryptState(state, password);
      const passwordsMatch = decrypted.password === password;
      if (passwordsMatch) {
        const wallets = (decrypted.wallets as PlugWallet[]).map(
          wallet =>
            new PlugWallet({
              ...wallet,
              mnemonic: decrypted.mnemonic as string,
            })
        );
        this.state = { ...decrypted, wallets };
      }
    }
  };

  public create = async ({
    password = '',
  }: {
    password: string;
  }): Promise<{ wallet: PlugWallet; mnemonic: string }> => {
    const { mnemonic } = createAccount(password);
    const wallet = await this.createAndPersistKeyRing({ mnemonic, password });
    return { wallet, mnemonic };
  };

  // CHECK WITH JANISON: What if they import the mnemonic in another place and put a different password? wouldn't that create a different account? (check seed derivation)
  public importMnemonic = async ({
    mnemonic,
    password,
  }: {
    mnemonic: string;
    password: string;
  }): Promise<PlugWallet> =>
    this.createAndPersistKeyRing({ mnemonic, password });

  // Assumes the state is already initialized
  public createPrincipal = async (): Promise<PlugWallet> => {
    this.checkInitialized();
    const wallet = new PlugWallet({
      mnemonic: this.state.mnemonic as string,
      walletNumber: this.state.wallets.length,
    });
    (this.state.wallets as PlugWallet[]).push(wallet);
    await this.storeState(this.state, this.state.password);
    return wallet;
  };

  public getState = async (): Promise<PlugState> => {
    if (!this.isUnlocked) {
      throw new Error('The state is locked');
    }
    await this.loadFromPersistance(this.state.password as string);
    return this.state;
  };

  public setCurrentPrincipal = (wallet: PlugWallet): void => {
    this.checkInitialized();
    this.state.currentWalletId = wallet.walletNumber;
  };

  public unlock = async (password: string): Promise<boolean> => {
    this.checkInitialized();
    await this.loadFromPersistance(password);
    this.isUnlocked = this.state?.password === password;
    return this.isUnlocked;
  };

  public lock = (): void => {
    this.isUnlocked = false;
    this.state = { wallets: [] };
  };

  private checkInitialized = (): void => {
    if (!this.state?.wallets?.length) {
      throw new Error('Plug must be initialized');
    }
  };

  private createAndPersistKeyRing = async ({
    mnemonic,
    password,
  }): Promise<PlugWallet> => {
    if (!password) throw new Error('A password is required');
    const wallet = new PlugWallet({ mnemonic, walletNumber: 0 });
    const data = {
      wallets: [wallet.toJSON()],
      currentWalletId: 0,
      password,
      mnemonic,
    };
    await this.storeState(data, password);
    await this.loadFromPersistance(password);
    return wallet;
  };

  private storeState = async (newState, password): Promise<void> => {
    const stringData = JSON.stringify({ ...this.state, ...newState });
    const encrypted = CryptoJS.AES.encrypt(stringData, password);
    await store.set(encrypted);
  };

  private decryptState = (state, password): PlugState =>
    JSON.parse(
      CryptoJS.AES.decrypt(state, password).toString(CryptoJS.enc.Utf8)
    );
}

export default PlugKeyRing;
