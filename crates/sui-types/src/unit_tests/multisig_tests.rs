// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    base_types::SuiAddress,
    crypto::{get_key_pair, Signature, SuiKeyPair},
    intent::{Intent, IntentMessage, PersonalMessage},
    multisig::AuthenticatorTrait,
};

use super::{MultiPublicKey, MultiSignature};

#[test]
fn multisig_2_of_3() {
    let ed_kp: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair().1);
    let k1_kp: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair().1);
    let r1_kp: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair().1);

    let pk1 = ed_kp.public();
    let pk2 = k1_kp.public();
    let pk3 = r1_kp.public();

    let multi_pk = MultiPublicKey::new(vec![pk1, pk2, pk3], 2);
    let addr = SuiAddress::from(multi_pk.clone());
    let msg = IntentMessage::new(
        Intent::default(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let sig1 = Signature::new_secure(&msg, &ed_kp);
    let sig2 = Signature::new_secure(&msg, &k1_kp);
    let sig3 = Signature::new_secure(&msg, &r1_kp);

    let multisig1 = MultiSignature::combine(vec![sig1.clone(), sig2.clone()], multi_pk.clone());
    assert!(multisig1.verify_secure_generic(&msg, addr).is_ok());

    let multisig2 = MultiSignature::combine(vec![sig1, sig3.clone()], multi_pk.clone());
    assert!(multisig2.verify_secure_generic(&msg, addr).is_ok());

    let multisig3 = MultiSignature::combine(vec![sig2.clone(), sig3], multi_pk.clone());
    assert!(multisig3.verify_secure_generic(&msg, addr).is_ok());

    let multisig3 = MultiSignature::combine(vec![sig2], multi_pk);
    assert!(multisig3.verify_secure_generic(&msg, addr).is_err());
}
