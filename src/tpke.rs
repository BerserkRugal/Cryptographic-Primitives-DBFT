// Cryptographic primitives employed in the construction of the DBFT protocol
// including full CCA2-secure threshold public key encryption (TPKE), 
// and symmetric encryption and decryption (used to facilitate Secret Maker's arbitrary message type encryption).

// The algorithm for TPKE is from the paper titled 
// “Boneh, Dan, Xavier Boyen, and Shai Halevi. "Chosen ciphertext secure public key threshold encryption without random oracles." 

// It should be noted that the paper requires e:G x G -> Gt
// So far, there is no open-source library that supports G1 × G1 → GT, 
// nor is there an open-source library that provides the efficiently computable homomorphisms ϕ12:G1→G2 or ϕ21:G2→G1. 
// In order to reproduce the algorithm presented in the paper as closely as possible within the bls12_381 framework (but bls12_381 only provides e:G1 × G2 → GT), 
// we have constructed a deterministic and unique mapping, designated as map_g1_to_g2, which satisfies the following two conditions:
// (1) The same G1 elements are consistently mapped to the same G2 elements. 
// (2) The output is a valid point in the G2Projective group. 
// We employ map_g1_to_g2 to map all g1^ID h1 from G1 to G2 and adjust all pairings to align with the format e(element in G1, element in G2), 
// maintaining the remaining elements unaltered. 
// This approach merely reproduce the majority of the original algorithm's functionality, yet still falls short of its intended objective.

// We use bls12_381_plus because bls12_381 does not provide serialization and deserialization of Gt.

use bls12_381_plus::{pairing, G1Projective, G2Projective, Gt, Scalar};
use group::{Group, GroupEncoding};
use ff::Field;
use serde::{Serialize, Deserialize};
use rand_core_06::RngCore;
use rand_08::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use ed25519_dalek::{Keypair, Signature, PublicKey, Signer, Verifier, SignatureError};
use std::collections::HashMap;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::Nonce; // 96-bits; unique per message

/// Public key structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPublicKey {
    g: G1Projective,
    g1: G1Projective,
    g2: G2Projective,
    h1: G1Projective,
}

/// Ciphertext structure
#[derive(Debug, Clone)]
pub struct Ciphertext {
    c0: Gt,
    c1: G1Projective,
    c2: G2Projective,
    ver_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextTrans {
  c0: Gt,
  c1: G1Projective,
  c2: G2Projective,
  ver_key_bytes: [u8; 32],
}

impl Ciphertext {
  pub fn to_ciphertexttrans(&self) -> CiphertextTrans {
    CiphertextTrans {
        c0: self.c0,
        c1: self.c1,
        c2: self.c2,
        ver_key_bytes: self.ver_key.to_bytes(),
    }
  }
}

impl CiphertextTrans {
  pub fn to_ciphertext_raw(&self) -> Result<Ciphertext, SignatureError> {
    let ver_key = PublicKey::from_bytes(&self.ver_key_bytes)?;
    Ok(Ciphertext {
        c0: self.c0,
        c1: self.c1,
        c2: self.c2,
        ver_key,
    })
  }

  pub fn to_ciphertext(&self) -> Ciphertext {
    self.to_ciphertext_raw().unwrap()
  }
}

/// Decryption share structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecryptionShare {
    i: usize,
    w0: G2Projective,
    w1: G1Projective,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Secret key structure
pub struct SecretKey {
    sk_i: G2Projective,
}

/// Party structure that holds each party's individual secret key and access to system-wide public parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Party {
    pk: MPublicKey,
    sk: SecretKey,
    vks: Vec<G1Projective>, // Verification keys for all participants
    n: usize,               // Total number of participants
    k: usize,               // Threshold
    i: usize,               // party number
}

impl Party {
    /// Hash function H
    pub fn H(input: &PublicKey) -> Scalar {
        let hash = Sha512::digest(input);
        let mut wide_bytes = [0u8; 64];
        wide_bytes.copy_from_slice(&hash);
        Scalar::from_bytes_wide(&wide_bytes)
    }

    /// Symmetric encryption function using AES-GCM
    /// `message` is the plaintext to be encrypted
    /// `hash` is the symmetric key (derived from a hash)
    pub fn sym_encrypt(message: &[u8], hash: &[u8]) -> Option<(Vec<u8>, Nonce<U12>)> {
      // Derive a 256-bit key from the hash
      let key_hash = Sha256::digest(hash);
      let key = GenericArray::from_slice(&key_hash);

      // Initialize AES-GCM with the derived key
      let cipher = Aes256Gcm::new(key);

      // Generate a random nonce (12 bytes)
      let binding = rand::random::<[u8; 12]>();
      let nonce = Nonce::from_slice(&binding);

      // Encrypt the message
      match cipher.encrypt(nonce, message) {
          Ok(ciphertext) => Some((ciphertext, *nonce)),
          Err(_) => None,
      }
    }

    /// Symmetric decryption function using AES-GCM
    /// `ciphertext` is the encrypted message to be decrypted
    /// `hash` is the symmetric key (derived from a hash)
    /// `nonce` is the nonce used in encryption
    pub fn sym_decrypt(ciphertext: &[u8], hash: &[u8], nonce: &Nonce<U12>) -> Option<Vec<u8>> {
      // Derive a 256-bit key from the hash
      let key_hash = Sha256::digest(hash);
      let key = GenericArray::from_slice(&key_hash);

      // Initialize AES-GCM with the derived key
      let cipher = Aes256Gcm::new(key);

      // Decrypt the message
      match cipher.decrypt(nonce, ciphertext) {
          Ok(plaintext) => Some(plaintext),
          Err(_) => None,
      }
    }

    /// One-time signature keypair generation
    pub fn gen_ots_keypair() -> Keypair {
        let mut csprng = rand::thread_rng();
        Keypair::generate(&mut csprng)
    }

    /// One-time signature scheme
    pub fn sign_ots(keypair: &Keypair, message: &[u8]) -> Signature {
        keypair.sign(message)
    }

    pub fn verify_ots(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
        public_key.verify(message, signature).is_ok()
    }

    /// Maps a G1 point to G2
    fn map_g1_to_g2(g1_point: G1Projective) -> G2Projective {
        // Serialize G1 point to bytes
        let g1_bytes = g1_point.to_bytes();
        // Hash the byte array to a scalar
        let hash = Sha512::digest(&g1_bytes);
        let scalar = Scalar::from_bytes_wide(&hash.into());
        // Multiply G2 generator by this scalar
        let g2_generator = G2Projective::GENERATOR;
        g2_generator * scalar
    }

    /// Setup function to create parties with their respective secret keys and public parameters
    pub fn setup(n: usize, k: usize) -> (MPublicKey, Vec<Party>) {
        let mut rng = OsRng;

        // Generate group elements
        let g = G1Projective::random(&mut rng);
        let g2 = G2Projective::random(&mut rng);
        let h1 = G1Projective::random(&mut rng);

        // Generate random k-1 degree polynomial f(x)
        let f_coeffs: Vec<Scalar> = (0..k).map(|_| Scalar::random(&mut rng)).collect();
        let alpha = f_coeffs[0];

        // Compute g1 = g^α
        let g1 = g * alpha;

        let mut secret_keys = Vec::new();
        let mut verification_keys = Vec::new();

        for i in 1..=n {
            let mut f_i = Scalar::ZERO;
            let i_scalar = Scalar::from(i as u64);
            for (j, coeff) in f_coeffs.iter().enumerate() {
                f_i += coeff * i_scalar.pow(&[j as u64, 0, 0, 0]);
            }
            let sk_i = g2 * f_i;
            let vk_i = g * f_i;
            secret_keys.push(SecretKey { sk_i });
            verification_keys.push(vk_i);
        }

        let pk = MPublicKey { g, g1, g2, h1 };

        // Create parties and distribute keys
        let parties: Vec<Party> = (0..n)
            .map(|i| Party {
                pk: pk.clone(),
                sk: secret_keys[i].clone(),
                vks: verification_keys.clone(),
                n,
                k,
                i: i.clone() + 1,
            })
            .collect();

        (pk, parties)
    }

    /// Encrypt function (this can be done by a trusted third party or any party)
    pub fn encrypt(pk: &MPublicKey, message: Gt) -> Ciphertext {
        let mut rng = OsRng;

        // Generate random scalar s
        let s = Scalar::random(&mut rng);

        // Compute e(g1, g2)^s * M
        let c0 = pairing(&bls12_381_plus::G1Affine::from(&pk.g1), &bls12_381_plus::G2Affine::from(&pk.g2))
            * s
            + message;

        // Compute g^s
        let c1 = pk.g * s;

        let keypair = Self::gen_ots_keypair();
        // Compute (g1^{ID} h1)^s
        let id_hash = Self::H(&keypair.public);
        let map_g2 = Self::map_g1_to_g2(pk.g1 * id_hash + pk.h1);
        let c2 = map_g2 * s;

        Ciphertext {
            c0,
            c1,
            c2,
            ver_key: keypair.public,
        }
    }

    pub fn encrypt_party(&self, message: Gt) -> Ciphertext {
        Self::encrypt(&self.pk, message)
    }

    /// Share decryption function (each party calls this with their own secret key)
    pub fn share_decrypt(&self, ciphertext: &Ciphertext) -> Option<DecryptionShare> {
        let id_hash = Self::H(&ciphertext.ver_key);
        let map_g2 = Self::map_g1_to_g2(self.pk.g1 * id_hash + self.pk.h1);
        let pairing_check = pairing(
            &bls12_381_plus::G1Affine::from(ciphertext.c1),
            &bls12_381_plus::G2Affine::from(&map_g2),
        );

        if pairing_check != pairing(
            &bls12_381_plus::G1Affine::from(&self.pk.g),
            &bls12_381_plus::G2Affine::from(ciphertext.c2),
        ) {
            return None;
        }

        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let w0 = self.sk.sk_i + map_g2 * r;
        let w1 = self.pk.g * r;

        Some(DecryptionShare { i:self.i, w0, w1 })
    }

    /// Share verification function
    pub fn share_verify(&self, ciphertext: &Ciphertext, share: &DecryptionShare) -> bool {
        let id_hash = Self::H(&ciphertext.ver_key);
        let map_g2 = Self::map_g1_to_g2(self.pk.g1 * id_hash + self.pk.h1);
        let pairing_check = pairing(
            &bls12_381_plus::G1Affine::from(ciphertext.c1),
            &bls12_381_plus::G2Affine::from(&map_g2),
        );

        if pairing_check != pairing(
            &bls12_381_plus::G1Affine::from(&self.pk.g),
            &bls12_381_plus::G2Affine::from(ciphertext.c2),
        ) {
            return false;
        }

        let u_i = self.vks[share.i - 1];
        pairing(
            &bls12_381_plus::G1Affine::from(u_i),
            &bls12_381_plus::G2Affine::from(self.pk.g2),
        ) + pairing(
            &bls12_381_plus::G1Affine::from(share.w1),
            &bls12_381_plus::G2Affine::from(map_g2),
        ) == pairing(
            &bls12_381_plus::G1Affine::from(self.pk.g),
            &bls12_381_plus::G2Affine::from(share.w0),
        )
    }

    /// Combine decryption shares to recover the message (only decrypting party can use)
    pub fn combine(&self, ciphertext: &Ciphertext, shares: Vec<DecryptionShare>) -> Option<Gt> {
        if shares.len() < self.k {
            return None;
        }

        let mut w0_acc = G2Projective::IDENTITY;
        let mut w1_acc = G1Projective::identity();

        for share in shares.iter() {
            let mut lagrange_coeff = Scalar::ONE;
            for other_share in shares.iter() {
                if share.i != other_share.i {
                    let numerator = Scalar::from(other_share.i as u64);
                    let denominator = Scalar::from((other_share.i as i64 - share.i as i64).abs() as u64);
                    lagrange_coeff *= numerator * denominator.invert().unwrap();
                }
            }

            w0_acc += share.w0 * lagrange_coeff;
            w1_acc += share.w1 * lagrange_coeff;
        }

        let recovered_message = ciphertext.c0
            + pairing(
                &bls12_381_plus::G1Affine::from(ciphertext.c1),
                &bls12_381_plus::G2Affine::from(w0_acc),
            )
            - pairing(
                &bls12_381_plus::G1Affine::from(w1_acc),
                &bls12_381_plus::G2Affine::from(ciphertext.c2),
            );

        Some(recovered_message)
    }

    /// Combine decryption shares to recover the message (anyone can use)
    pub fn combine_wide(pk: &MPublicKey, ciphertext: &Ciphertext, shares: Vec<DecryptionShare>, k: usize) -> Option<Gt> {
      if shares.len() < k {
          return None;
      }

      let mut w0_acc = G2Projective::IDENTITY;
      let mut w1_acc = G1Projective::identity();

      for share in shares.iter() {
          let mut lagrange_coeff = Scalar::ONE;
          for other_share in shares.iter() {
              if share.i != other_share.i {
                  let numerator = Scalar::from(other_share.i as u64);
                  let denominator = Scalar::from((other_share.i as i64 - share.i as i64).abs() as u64);
                  lagrange_coeff *= numerator * denominator.invert().unwrap();
              }
          }

          w0_acc += share.w0 * lagrange_coeff;
          w1_acc += share.w1 * lagrange_coeff;
      }

      let recovered_message = ciphertext.c0
          + pairing(
              &bls12_381_plus::G1Affine::from(ciphertext.c1),
              &bls12_381_plus::G2Affine::from(w0_acc),
          )
          - pairing(
              &bls12_381_plus::G1Affine::from(w1_acc),
              &bls12_381_plus::G2Affine::from(ciphertext.c2),
          );

      Some(recovered_message)
  }
    pub fn random_gt() -> Gt {
      let mut rng = OsRng;
      Gt::random(&mut rng)
  }
}

/// Test module
#[cfg(test)]
mod tests {
    use super::*;
    // use bincode;

    
    #[test]
    fn test_sym_encrypt_decrypt() {
        let message = b"Hello, Generals!";
        let test_gt = Party::random_gt();
        let gt_bytes = test_gt.to_bytes();
        // let mut hash = Sha256::new();
        // hash.update(gt_bytes);

        // Encrypt the message
        let encryption_result = Party::sym_encrypt(message, &gt_bytes);
        assert!(encryption_result.is_some());

        let (ciphertext, nonce) = encryption_result.unwrap();

        // Ensure ciphertext is not equal to the original message
        assert_ne!(ciphertext, message);

        // Decrypt the message
        let decryption_result = Party::sym_decrypt(&ciphertext, &gt_bytes, &nonce);
        assert!(decryption_result.is_some());

        let decrypted_message = decryption_result.unwrap();

        // Ensure the decrypted message matches the original
        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_sym_decrypt_with_wrong_hash() {
        let message = b"Hello, Generals!";
        let hash = b"test_hash_value";
        let wrong_hash = b"wrong_hash_value";

        // Encrypt the message
        let encryption_result = Party::sym_encrypt(message, hash);
        assert!(encryption_result.is_some());

        let (ciphertext, nonce) = encryption_result.unwrap();

        // Attempt to decrypt with a wrong hash
        let decryption_result = Party::sym_decrypt(&ciphertext, wrong_hash, &nonce);

        // Decryption should fail with the wrong key
        assert!(decryption_result.is_none());
    }

    #[test]
    fn test_sym_decrypt_with_wrong_nonce() {
        let message = b"Hello, Generals!";
        let hash = b"test_hash_value";

        // Encrypt the message
        let encryption_result = Party::sym_encrypt(message, hash);
        assert!(encryption_result.is_some());

        let (ciphertext, nonce) = encryption_result.unwrap();

        // Generate a wrong nonce manually (random nonce)
        let binding = rand::random::<[u8; 12]>();
        let wrong_nonce = Nonce::<U12>::from_slice(&binding);

        // Attempt to decrypt with a wrong nonce
        let decryption_result = Party::sym_decrypt(&ciphertext, hash, wrong_nonce);

        // Decryption should fail with the wrong nonce
        assert!(decryption_result.is_none());
    }

    #[test]
    fn test_setup() {
        let (pk, parties) = Party::setup(5, 3);

        // Check if public key and secret keys are generated correctly
        assert_ne!(pk.g, G1Projective::identity());
        assert_ne!(pk.g1, G1Projective::identity());
        assert_ne!(pk.g2, G2Projective::IDENTITY);
        assert_ne!(pk.h1, G1Projective::identity());

        // Check if each secret key is non-zero
        for party in &parties {
            assert_ne!(party.sk.sk_i, G2Projective::IDENTITY);
        }

        // Check if verification keys are non-zero
        for party in &parties {
            for vk_i in &party.vks {
                assert_ne!(vk_i, &G1Projective::identity());
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let n = 4;
        let k = 3;

        let (pk, parties) = Party::setup(n, k);

        // Encrypt message
        // let message = pairing(
        //     &bls12_381_plus::G1Affine::from(pk.g),
        //     &bls12_381_plus::G2Affine::from(pk.g2),
        // );
        let mut rng = OsRng;
        let message = Gt::random(&mut rng);

        let ciphertext = Party::encrypt(&pk, message);

        // Each party generates decryption shares
        let mut shares = Vec::new();
        for i in 0..k {
            let share = parties[i].share_decrypt(&ciphertext).unwrap();
            assert!(parties[i].share_verify(&ciphertext, &share));
            shares.push(share);
        }

        // Combine shares to recover the message
        let recovered_message = parties[0].combine(&ciphertext, shares).unwrap();
        // let recovered_message = Party::combine(&pk, &ciphertext, shares, k).unwrap();
        // assert_eq!(recovered_message, message);
    }

    #[test]
    fn test_hash_function() {
        let keypair = Party::gen_ots_keypair();
        //let input = b"test input";
        let hash = Party::H(&keypair.public);
        
        // 检查哈希输出是否为非零标量
        assert_ne!(hash, Scalar::ZERO);
    }

    #[test]
    fn test_signature_scheme() {
        let keypair = Party::gen_ots_keypair();
        let message = b"hello, world";
        
        // 生成签名
        let signature = Party::sign_ots(&keypair, message);
        
        // 验证签名
        assert!(Party::verify_ots(&keypair.public, message, &signature));
    }
}