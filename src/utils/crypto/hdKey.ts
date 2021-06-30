import * as bip39 from 'bip39';

import ExtendedKey from './extendedKey';
import { DERIVATION_PATH } from '../account/constants';

const bigValue = 0x80000000;

interface KeyPair {
  privateKey: any;
  publicKey: any;
}

const isValidPath = (path: string): boolean => {
  if (!new RegExp("^m(\\/[0-9]+')+$").test(path)) {
    return false;
  }
  return !path
    .split('/')
    .slice(1)
    .map(el => el.replace("'", ''))
    .some(Number.isNaN as any /* ts T_T */);
};

const parseDerivationPath = (derivationPath: string): number[] => {
  if (!isValidPath(derivationPath)) {
    throw new Error('Invalid derivation path');
  }

  const components = derivationPath.split('/').slice(1);
  const result = components.map(comp => {
    const hasSufix = comp.indexOf("'") >= 0;
    let value = parseInt(comp.replace("'", ''), 10);
    if (hasSufix) value += bigValue;
    return value;
  });
  return result;
};

export const deriveMasterXPrivKey = (
  mnemonic: string,
  path: string
): ExtendedKey => {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const masterXKey = ExtendedKey.newMasterKey(seed);

  parseDerivationPath(path).forEach(pathIndx => masterXKey.derive(pathIndx));

  return masterXKey;
};

export const deriveGrandchildECKeyPair = (
  extendeKey: ExtendedKey,
  index: number
): KeyPair => {
  extendeKey.derive(0);
  extendeKey.derive(index);
  return {
    privateKey: extendeKey.secretKey(),
    publicKey: extendeKey.publicKey(),
  };
};

export const generateKeyPair = (mnemonic: string, index: number): KeyPair => {
  const extendedKey = deriveMasterXPrivKey(mnemonic, DERIVATION_PATH);
  return deriveGrandchildECKeyPair(extendedKey, index);
};

export default {};
