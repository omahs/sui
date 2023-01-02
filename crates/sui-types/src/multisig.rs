// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{crypto::SuiSignature, sui_serde::SuiBitmap};
use derive_more::From;
pub use enum_dispatch::enum_dispatch;
use fastcrypto::{
    bls12381::min_sig::{BLS12381PublicKey, BLS12381Signature},
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    encoding::Base64,
    secp256k1::{Secp256k1PublicKey, Secp256k1Signature},
    secp256r1::{Secp256r1PublicKey, Secp256r1Signature},
    traits::ToFromBytes,
    Verifier,
};
use roaring::RoaringBitmap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::hash::{Hash, Hasher};

use crate::{
    base_types::SuiAddress,
    crypto::{PublicKey, Signature},
    error::SuiError,
    intent::IntentMessage,
};

#[cfg(test)]
#[path = "unit_tests/multisig_tests.rs"]
mod multisig_tests;

#[enum_dispatch]
pub trait AuthenticatorTrait {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize;
}

#[enum_dispatch(AuthenticatorTrait)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, JsonSchema, Hash)]
#[serde(untagged)]
pub enum GenericSignature {
    MultiSignature,
    Signature,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct MultiSignature {
    sigs: Vec<CompressedSignature>,
    #[schemars(with = "Base64")]
    #[serde_as(as = "SuiBitmap")]
    bitmap: RoaringBitmap,
    multi_pk: MultiPublicKey,
}

impl PartialEq for MultiSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sigs == other.sigs && self.bitmap == other.bitmap && self.multi_pk == other.multi_pk
    }
}
impl Eq for MultiSignature {}

impl Hash for MultiSignature {
    fn hash<H: Hasher>(&self, _state: &mut H) {
        todo!()
    }
}

impl MultiSignature {
    pub fn is_valid(&self) -> Result<(), SuiError> {
        // if self.sigs.len() != self.bitmap.len() {
        //     return Err(SuiError::InvalidSignature {
        //         error: format!("Invalid number of signatures"),
        //     });
        // }
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.sigs.len()
    }
}

#[derive(Debug, From, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub enum CompressedSignature {
    #[schemars(with = "Base64")]
    Ed25519(Ed25519Signature),
    #[schemars(with = "Base64")]
    Secp256k1(Secp256k1Signature),
    #[schemars(with = "Base64")]
    Secp256r1(Secp256r1Signature),
    #[schemars(with = "Base64")]
    BLS12381(BLS12381Signature),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MultiPublicKey {
    pub pks: Vec<PublicKey>,
    pub threshold: usize,
}

impl MultiPublicKey {
    pub fn new(pks: Vec<PublicKey>, threshold: usize) -> Self {
        MultiPublicKey { pks, threshold }
    }

    pub fn get_index(&self, pk: PublicKey) -> Option<u32> {
        self.pks.iter().position(|x| *x == pk).map(|x| x as u32)
    }
}

impl AuthenticatorTrait for MultiSignature {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        let th = &self.multi_pk.threshold;
        if th > &self.size() {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of signatures".to_string(),
            });
        }

        if <SuiAddress as From<MultiPublicKey>>::from(self.multi_pk.clone()) != author {
            return Err(SuiError::InvalidSignature {
                error: "Invalid address".to_string(),
            });
        }
        let mut count = 0;
        let msg = &bcs::to_bytes(value).unwrap();

        for (sig, i) in self.sigs.iter().zip(&self.bitmap) {
            let pk = self
                .multi_pk
                .pks
                .get(i as usize)
                .ok_or(SuiError::InvalidSignature {
                    error: "Invalid signature index".to_string(),
                })
                .unwrap();
            let res = match sig {
                CompressedSignature::Ed25519(s) => {
                    let pk = Ed25519PublicKey::from_bytes(pk.as_ref())
                        .map_err(|_| SuiError::InvalidSignature {
                            error: "Invalid signature".to_string(),
                        })
                        .unwrap();
                    pk.verify(msg, s)
                }
                CompressedSignature::Secp256k1(s) => {
                    let pk = Secp256k1PublicKey::from_bytes(pk.as_ref())
                        .map_err(|_| SuiError::InvalidSignature {
                            error: "Invalid signature".to_string(),
                        })
                        .unwrap();
                    pk.verify(msg, s)
                }
                CompressedSignature::Secp256r1(s) => {
                    let pk = Secp256r1PublicKey::from_bytes(pk.as_ref())
                        .map_err(|_| SuiError::InvalidSignature {
                            error: "Invalid signature".to_string(),
                        })
                        .unwrap();
                    pk.verify(msg, s)
                }
                CompressedSignature::BLS12381(s) => {
                    let pk = BLS12381PublicKey::from_bytes(pk.as_ref())
                        .map_err(|_| SuiError::InvalidSignature {
                            error: "Invalid signature".to_string(),
                        })
                        .unwrap();
                    pk.verify(msg, s)
                }
            };
            if res.is_ok() {
                count += 1
            }
        }

        if count >= self.multi_pk.threshold {
            Ok(())
        } else {
            Err(SuiError::InvalidSignature {
                error: "Invalid number of signatures".to_string(),
            })
        }
    }
}
impl MultiSignature {
    #[allow(dead_code)]
    fn combine(full_sigs: Vec<Signature>, multi_pk: MultiPublicKey) -> Self {
        let mut bitmap = RoaringBitmap::new();
        let mut sigs = Vec::new();
        full_sigs.iter().for_each(|s| {
            bitmap.insert(multi_pk.get_index(s.to_public_key()).unwrap());
            sigs.push(s.to_compressed());
        });

        MultiSignature {
            sigs,
            bitmap,
            multi_pk,
        }
    }
}

/// Port to the verify_secure defined on Single Signature.
impl AuthenticatorTrait for Signature {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        self.verify_secure(value, author)
    }
}
