// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use enum_dispatch::enum_dispatch;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use pv::request::{Confidential, SymKey};

use super::Error;
use crate::pv_utils::{
    error::Result,
    se_hdr::SeHdrData,
    uvdata::{AeadCipherTrait, UvDataPlainTrait},
};

#[enum_dispatch]
pub trait AeadCipherBuilderTrait: AeadCipherTrait {
    fn set_iv(&mut self, iv: &[u8]) -> Result<()>;
    fn generate_aead_key(&self) -> Result<SymKey> {
        Ok(SymKey::random(self.aead_key_type())?)
    }
}

/// Key exchange related methods
#[enum_dispatch]
pub trait KeyExchangeBuilderTrait {
    fn add_keyslot(
        &mut self,
        hostkey: &PKeyRef<Public>,
        aead_key: &SymKey,
        priv_key: &PKeyRef<Private>,
    ) -> Result<()>;
    fn clear_keyslots(&mut self) -> Result<()>;
    fn generate_private_key(&self) -> Result<PKey<Private>>;
    fn set_cust_public_key(&mut self, key: &PKeyRef<Private>) -> Result<()>;
}

pub struct UvDataBuilder<
    'a,
    T: KeyExchangeBuilderTrait + AeadCipherBuilderTrait,
    K = PKeyRef<Public>,
    P = PKey<Private>,
> {
    pub(crate) expert_mode: bool,
    pub(crate) prot_key: SymKey,
    pub(crate) priv_key: P,
    pub(crate) target_keys: Vec<&'a K>,
    pub(crate) plain_data: T,
}

impl<T: KeyExchangeBuilderTrait + AeadCipherBuilderTrait, K, P> UvDataBuilder<'_, T, K, P> {
    /// Enable expert mode - this is required for specifying PSW, etc.
    pub fn i_know_what_i_am_doing(&mut self) {
        self.expert_mode = true;
    }
}

impl<T: std::fmt::Debug + KeyExchangeBuilderTrait + AeadCipherBuilderTrait + UvDataPlainTrait>
    std::fmt::Debug for UvDataBuilder<'_, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UvDataBuilder")
            .field("expert_mode", &self.expert_mode)
            .field("prot_key", &self.prot_key)
            .field("plain_data", &self.plain_data)
            .finish()
    }
}

impl<'a, T: KeyExchangeBuilderTrait + AeadCipherBuilderTrait> UvDataBuilder<'a, T> {
    pub fn add_hostkeys<P: AsRef<PKeyRef<Public>>>(
        &mut self,
        hostkeys: &'a [P],
    ) -> Result<&mut Self> {
        for hk in hostkeys {
            self.plain_data
                .add_keyslot(hk.as_ref(), &self.prot_key, &self.priv_key)?;
            self.target_keys.push(hk.as_ref());
        }

        Ok(self)
    }

    pub fn with_iv(&mut self, iv: &[u8]) -> Result<&mut Self> {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        self.plain_data.set_iv(iv)?;
        Ok(self)
    }

    fn update_target_key_slots(&mut self) -> Result<()> {
        self.plain_data.clear_keyslots()?;
        for hk in &self.target_keys {
            self.plain_data
                .add_keyslot(hk, &self.prot_key, &self.priv_key)?;
        }
        Ok(())
    }

    pub fn with_aead_key(&mut self, data: Confidential<Vec<u8>>) -> Result<&mut Self> {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        let key = SymKey::try_from_data(self.plain_data.aead_key_type(), data)?;
        self.prot_key = key;
        self.update_target_key_slots()?;

        Ok(self)
    }

    pub fn with_priv_key(&mut self, priv_key: &PKeyRef<Private>) -> Result<&mut Self> {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        self.plain_data.set_cust_public_key(priv_key)?;
        self.priv_key = priv_key.to_owned();
        self.update_target_key_slots()?;

        Ok(self)
    }

    pub const fn prot_key(&self) -> &SymKey {
        &self.prot_key
    }

    pub fn priv_key(&self) -> &PKeyRef<Private> {
        self.priv_key.as_ref()
    }
}

/// A trait for the builder pattern.
pub trait BuilderTrait {
    /// Data structure to construct
    type T;

    /// Builds the type [`Self::T`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the data structure could not be
    /// build.
    fn build(self) -> Result<Self::T>;
}
