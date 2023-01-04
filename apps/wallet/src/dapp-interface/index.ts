// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { registerWallet } from '@mysten/wallet-standard';

import { DAppInterface } from './DAppInterface';
import { SuiWallet } from './WalletStandardInterface';

registerWallet(new SuiWallet());

let deprecationNotified = false;
try {
    Object.defineProperty(window, 'suiWallet', {
        enumerable: false,
        configurable: false,
        value: new Proxy(new DAppInterface(), {
            get: (target, prop) => {
                if (!deprecationNotified) {
                    console.warn(
                        'Using the injected DAppInterface, (window.suiWallet) is deprecated. Use WalletStandardInterface, see more here https://github.com/MystenLabs/sui/tree/main/sdk/wallet-adapter.'
                    );
                    deprecationNotified = true;
                }
                // @ts-expect-error any
                return target[prop];
            },
        }),
    });
} catch (e) {
    // eslint-disable-next-line no-console
    console.warn(
        '[sui-wallet] Unable to attach to window.suiWallet. There are likely multiple copies of the Sui Wallet installed.'
    );
}
