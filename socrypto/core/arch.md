### Overview

Define core crypto abstraction and application layer api to be used in all SUPRA projects requiring any cryptographic
add-ins.
This way user will be isolated from core cryptographic concepts and will use well defined APIs,
and also the chances to misuse and alter crypto-core will be reduced.

### [`types`](src%2Ftypes) defines crypto-layer traits, signature schemes and their concrete implementations, helper types

- [`pub mod error`](src%2Ftypes%2Ferror.rs) defines `CryptoResult` and `CryptoError` types
- [`pub mod identity`](src%2Ftypes%2Fidentity.rs) defines unique identity concept for signers and helps to
  abstract from signature-scheme data-types
- [`pub mod order`](src%2Ftypes%2Forder.rs) defines order of the participants in scope of multi-party signature schemes
- [`pub mod digest`](src%2Ftypes%2Fdigest.rs) defines `Hash` type which represents hashed value as well
  as `Digest` trait
    - we may replace this with `UniqueHash` trait from `crypto` library as we integrate
- [`pub mod ownable`](src%2Ftypes%2Fownable.rs) defines API for the signers which provide means to prove the
  possession of secret key
- [`schemes`](src%2Ftypes%2Fschemes) - encloses generic definition of signature schemes
    - [`pub mod single_sig_scheme`](src%2Ftypes%2Fschemes%2Fsingle_sig_scheme.rs) provides
      crypto-layer `trait SignatureScheme` to describe generic single signature scheme
    - [`aggregated_signature_scheme`](src%2Ftypes%2Fschemes%2Faggregated_signature_scheme)
      provides crypto-layer `trait AggregateSignatureScheme` which captures generic interface of aggregate signatures
      schemes
      such as threshold signatures and extended version of it `trait MultiSignatureScheme` for multi-signatures.
- [`impls`](src%2Ftypes%2Fimpls) - encloses definition of concrete implementations of signature schemes defined
  in `types::schemes`
    - [`pub mod sig_ecdsa_ed25519`](src%2Ftypes%2Fimpls%2Fsig_ecdsa_ed25519) defines concrete instantiation of
      SignatureScheme using ECDSA signatures on ED25519 curve
    - [`pub mod multisig_bls`](src%2Ftypes%2Fimpls%2Fmultisig_bls) - defines multi-signature schemes based on BLS curves
    - [`pub mod threshold_bls`](src%2Ftypes%2Fimpls%2Fthreshold_bls) - defines threshold signature schemes based on
      various BLS curves
    - [`helpers`](src%2Ftypes%2Fimpls%2Fhelpers) provides helper functions and wrapper types necessary
      for implementation

### [`api`](src%2Fapi) encloses crypto layer for application layer.

Defines wrappers with user-friendly interfaces and concrete instances of wrappers based on concrete implementations of
signature schemes for application layer abstracting user from internal crypto types.

- [`types`](src%2Fapi%2Ftypes) - encloses generic concepts of single and multi-parti signature schemes facing
  application layer
    - [`single_sig_types`](src%2Fapi%2Ftypes%2Fsingle_sig_types) describe wrapper structs of single signature
      scheme for application layer
        - Note that of the following, `PublicParametersWrapperSig` can exist in a different
          layer built on top of the other wrappers

        - **Signing Key Wrapper**

      ```rust
      pub struct SigningKeyWrapperSig<T: SignatureScheme>(pub(crate) T::SigningKeyType);
      
      impl<T: SignatureScheme> SigningKeyWrapperSig<T> {
          /// choose a new random secret key
          pub fn new() -> Self { ... }
          /// compute verification key associated with self
          pub fn gen_vk(&self) -> VerificationKeyWrapperSig<T> { ... }
          /// sign message `msg` using associated verification key `vk`
          pub fn sign(&self, msg: &[u8], vk: &VerificationKeyWrapperSig<T>) -> SignatureWrapper<T> { ... }
          ///
          pub fn sign_no_vk(&self, msg: &[u8]) -> SignatureWrapper<T> { ... }
      }
      ```

        - **Verification Key Wrapper**

      ```rust
      pub struct VerificationKeyWrapperSig<T: SignatureScheme>(pub(crate) T::VerificationKeyType);
      
      impl<T: SignatureScheme> VerificationKeyWrapperSig<T> {
          /// verify signature `sig` on message `msg` using `self` as verification key
          pub fn verify(&self, msg: &[u8], sig: &SignatureWrapper<T>) -> CryptoResult<()> { ... }
      }
      ```

        - **Signature Wrapper**

      ```rust
      pub struct SignatureWrapper<T: SignatureScheme>(pub(crate) T::SignatureType);
      
      impl<T: SignatureScheme> SignatureWrapper<T> {
          /// verify that `self` is a signature on message `msg` w.r.t. verification key `vk`
          pub fn verify(&self, msg: &[u8], vk: &VerificationKeyWrapperSig<T>) -> CryptoResult<()> { ... }
      }
      ```

        - **Pop Wrapper**

      ```rust
      pub struct PopWrapperSig<T: SignatureScheme>(pub(crate) T::PopType);
      
      impl<T: SignatureScheme> PopWrapperSig<T> {
          /// verifies `self` as proof of possession on verification key `vk`
          pub fn verify_possession(&self, vk: &VerificationKeyWrapperSig<T>) -> CryptoResult<()> { ... }
      }
      ```

        - **Public Parameters Wrapper**

      ```rust
      /// Set of Verification keys deterministically ordered based on their identity providing means to verify
      /// the signature based on identity or order of identity
      pub struct PublicParametersWrapperSig<T: SignatureScheme>(...);
      
      impl<T: SignatureScheme> PublicParametersWrapperSig<T> {
          /// initialize self from mapping of identities to verification keys
          pub fn new(id_map: HashMap<Identity, VerificationKeyWrapperSig<T>>) -> Self { ... }
          /// verify signature `sig` was signed with verification key corresponding to `id`
          pub fn verify_signature(&self, msg: &[u8], id: &Identity, sig: &SignatureWrapper<T>) -> CryptoResult<()> { ... }
          /// get the verification key associated with identity `id` if present
          pub fn get_vk(&self, id: &Digest) -> Option<VerificationKeyWrapperSig<T>> { ... }
      }
      ```

    - [`aggregated_signature_types`](src%2Fapi%2Ftypes%2Faggregated_signature_types)
      provides wrapper structs for multi-signer signature schemes for application layer.
        - Notes:
            - These types are not differentiated between threshold and muilti-signature schemes
            - Even though these are different wrapper structs from `SignatureScheme`, they maintain many of the
              same function names/parameters and ordering

        - **Signing Key Wrapper**

          ```rust  
          pub struct SigningKeyWrapperAggSig<T: AggregateSignatureScheme>(pub(crate) T::SigningKeyType);  
    
          /// As long as in case of threshold signatures signing key is generated among the participant based on initial negotiation  
          /// there is no direct API allowing to create signing key, it should be generated by specific API/means.  
          impl<T: AggregateSignatureScheme> SigningKeyWrapperAggSig<T> {  
              /// generate a partial signature on message `msg` using associated verification key `vk`  
              pub fn sign(&self, msg: &[u8], vk: &VerificationKeyWrapperAggSig<T>) -> PartialSignatureWrapper<T> { ... }  
          }  
    
          impl<T: MultiSignatureScheme> SigningKeyWrapperAggSig<T> {  
              /// choose a new random secret key  
              pub fn new() -> Self { ... }  
              /// compute verification key associated with self  
              pub fn gen_vk(&self) -> VerificationKeyWrapperAggSig<T> { ... }  
          }  
          ```  
        - **Verification Key Wrapper**

          ```rust  
          pub struct VerificationKeyWrapperAggSig<T: AggregateSignatureScheme>(pub(crate) T::VerificationKeyType);  
    
          impl<T: AggregateSignatureScheme> VerificationKeyWrapperAggSig<T> {  
              /// verify partial signature `sig` on message `msg` using `self` as verification key  
              pub fn verify(&self, msg: &[u8], sig: &PartialSignatureWrapper<T>) -> CryptoResult<()> { ... }  
          }  
          ```  
        - **Partial Signature Wrapper**

          ```rust  
          pub struct PartialSignatureWrapper<T: AggregateSignatureScheme>(pub(crate) T::PartialSignatureType);  
    
          impl<T: AggregateSignatureScheme> PartialSignatureWrapper<T> {  
              /// verify that `self` is a valid partial signature on message `msg` w.r.t. verification key `vk`  
              pub fn verify(&self, msg: &[u8], vk: &VerificationKeyWrapperAggSig<T>) -> CryptoResult<()> { ... }  
          }  
          impl<T: AggregateSignatureScheme> PartialSignatureWrapper<T> {  
              /// verify that `self` is a signature on message `msg` w.r.t. the verification key associated with `id`  
              pub fn verify_by_identity(&self, msg: &[u8], id: &Identity, pp: &PublicParametersWrapperAggSig<T>) -> CryptoResult<()> { ... }  
          }  
          ```  
        - **Aggregated Signature Wrapper**

          ```rust  
          pub struct AggregatedSignatureWrapper<T: AggregateSignatureScheme>(pub(crate) T::AggregatedSignatureType); // threshold_sig g1 multis  
    
          impl<T: AggregateSignatureScheme> AggregatedSignatureWrapper<T> {  
              /// verify that `self` is an aggregates signature on message `msg` w.r.t. public parameters `pp`  
              pub fn verify(&self, msg: &[u8], pp: &PublicParametersWrapperAggSig<T>) -> CryptoResult<()> { ... }  
          }  
          ```  
        - **Pop Wrapper**

          ```rust  
          pub struct PopWrapperAggSig<T: AggregateSignatureScheme>(pub(crate) T::PopType);  
    
          impl<T: AggregateSignatureScheme> PopWrapperAggSig<T> {  
              /// verifies `self` as proof of possession on verification key `vk`  
              pub fn verify_possession(&self, vk: &VerificationKeyWrapperAggSig<T>) -> CryptoResult<()> { ... }  
          }  
          ```  
        - **Public Parameters Wrapper**

          ```rust  
          pub struct PublicParametersWrapperAggSig<T: AggregateSignatureScheme>(pub(crate) T::PublicParametersType);  
    
          impl<T: AggregateSignatureScheme> PublicParametersWrapperAggSig<T> {  
              /// verify aggregate signature `sig` on message `msg` w.r.t. `self` as public parameters  
              pub fn verify_aggregated_signature(&self, msg: &[u8], sig: &AggregatedSignatureWrapper<T>) -> CryptoResult<()> { ... }  
              /// aggregate partial signatures using `self` as public parameters WITHOUT VALIDATING PSIGS  
              /// DO NOT USE UNLESS `sigs` CONTAINS ONLY VALID SIGS  
              pub fn aggregate_partial_sigs<  
                  I: IntoIterator<Item = (Identity, T::PartialSignatureType)>  
            >  (&self, msg: &[u8], psigs: I) -> CryptoResult<AggregatedSignatureWrapper<T>> { ... }  
              /// validates and aggregates partial signatures using `self` as public parameters  
              pub fn aggregate_and_validate_partial_sigs<  
                  I: IntoIterator<Item = (T::Identity, T::PartialSignatureType)>  
            >  (&self, msg: &[u8], psigs: I) -> CryptoResult<AggregatedSignatureWrapper<T>> { ... }  
              /// verify that `psig` is a partial signature on `msg` with respect to the verification key associated with `id`  
              pub fn verify_partial_signature_by_identity(&self, msg: &[u8], psig: &PartialSignatureWrapper<T>, id: &Identity) -> CryptoResult<()> { ... }  
              /// verify that `psig` is a partial signature on `msg` with respect to the verification key associated with `order`  
              pub fn verify_partial_signature_by_order(&self, msg: &[u8], psig: &PartialSignatureWrapper<T>, order: Order) -> CryptoResult<()> { ... }  
          }  
          ```  

- [`instances`](src%2Fapi%2Finstances) contains concrete instances of application-layer wrapper types based on concrete
  scheme implementation
    - [`pub mod bls_threshold_bls12381`](src%2Fapi%2Finstances%2Fbls_threshold_bls12381.rs)
    - [`pub mod bls_threshold_bn254`](src%2Fapi%2Finstances%2Fbls_threshold_bn254.rs)
    - [`pub mod bls_threshold_combined`](src%2Fapi%2Finstances%2Fbls_threshold_combined.rs)
    - [`pub mod bls_threshold_mcl`](src%2Fapi%2Finstances%2Fbls_threshold_mcl.rs)
    - [`pub mod ecdsa_sig_ed25519`](src%2Fapi%2Finstances%2Fecdsa_sig_ed25519.rs)
    - [`pub mod rev_bls_threshold_bls12381`](src%2Fapi%2Finstances%2Frev_bls_threshold_bls12381.rs)
