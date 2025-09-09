import { mnemonicToEntropy } from "bip39";
import { shake256 } from "@noble/hashes/sha3";
import { keccak256 } from "ethereum-cryptography/keccak";
import * as slh from "@noble/post-quantum/slh-dsa";
import { Buffer } from "buffer";

/**
 * SLH-DSA Wallet class that replaces ethers Wallet.fromMnemonic functionality
 * but uses post-quantum SLH-DSA keypairs instead of ECDSA
 */
class SLHWallet {
  constructor(address, privateKey, publicKey, privateKeyRaw, publicKeyRaw) {
    this.address = address;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.privateKeyRaw = privateKeyRaw;
    this.publicKeyRaw = publicKeyRaw;
  }

  /**
   * Create a wallet from mnemonic using SLH-DSA keypair derivation
   * @param {string} mnemonic - BIP39 mnemonic phrase
   * @returns {Promise<SLHWallet>} - Wallet instance with SLH-DSA derived address
   */
  static async fromMnemonic(mnemonic) {
    try {
      // Validate inputs
      if (!mnemonic || typeof mnemonic !== 'string') {
        throw new Error('Invalid mnemonic: must be a non-empty string');
      }
      
      if (typeof index !== 'number' || index < 0 || !Number.isInteger(index)) {
        throw new Error('Invalid index: must be a non-negative integer');
      }

      // Convert mnemonic to entropy
      const entropy = Buffer.from(mnemonicToEntropy(mnemonic), "hex");
      
      // Create derivation-specific entropy by combining original entropy with index
      const indexBuffer = Buffer.allocUnsafe(4);
      indexBuffer.writeUInt32BE(index, 0);
      const combinedEntropy = Buffer.concat([entropy, indexBuffer]);
      
      // Generate 96-byte seed using SHAKE256 with derivation-specific entropy
      const seed96 = shake256.create({ dkLen: 96 }).update(combinedEntropy).digest();
      
      // Generate SLH-DSA keypair
      const keys = slh.slh_dsa_shake_256f.keygen(seed96);

      // Process public key to generate Ethereum-compatible address
      const originalPublicKey = Buffer.from(keys.publicKey);
      
      // Strip the first byte (format identifier) from public key
      const strippedPubKey = originalPublicKey.subarray(1);

      // Generate Ethereum address using Keccak256
      const publicKeyHash = keccak256(strippedPubKey);
      const addressBytes = publicKeyHash.slice(-20);
      const address = bufferToHex(addressBytes);

      // Return new wallet instance
      return new SLHWallet(
        address.toLowerCase(),
        bufferToHex(keys.secretKey),
        bufferToHex(originalPublicKey),
        keys.secretKey,
        keys.publicKey
      );

    } catch (error) {
      throw new Error(`Failed to create wallet from mnemonic: ${error.message}`);
    }
  }

  /**
   * Sign a message using SLH-DSA
   * @param {string|Uint8Array} message - Message to sign
   * @returns {string} - Signature as hex string
   */
  async signMessage(message) {
    try {
      // Convert message to Uint8Array if it's a string
      const messageBytes = typeof message === 'string' 
        ? new TextEncoder().encode(message)
        : message;

      // Sign using SLH-DSA
      const signature = slh.slh_dsa_shake_256f.sign(this.privateKeyRaw, messageBytes);
      
      return bufferToHex(signature);
    } catch (error) {
      throw new Error(`Failed to sign message: ${error.message}`);
    }
  }

  /**
   * Verify a signature
   * @param {string|Uint8Array} message - Original message
   * @param {string|Uint8Array} signature - Signature to verify
   * @returns {boolean} - True if signature is valid
   */
  static verifySignature(message, signature, publicKey) {
    try {
      // Convert inputs to Uint8Array
      const messageBytes = typeof message === 'string' 
        ? new TextEncoder().encode(message)
        : message;
      
      const sigBytes = typeof signature === 'string'
        ? hexToBuffer(signature)
        : signature;
        
      const pubKeyBytes = typeof publicKey === 'string'
        ? hexToBuffer(publicKey)
        : publicKey;

      // Verify using SLH-DSA
      return slh.slh_dsa_shake_256f.verify(pubKeyBytes, messageBytes, sigBytes);
    } catch (error) {
      console.error('Signature verification failed:', error.message);
      return false;
    }
  }

  /**
   * Get wallet info as JSON
   * @returns {object} - Wallet information (excluding raw keys for security)
   */
  toJSON() {
    return {
      address: this.address,
      privateKey: this.privateKey,
      publicKey: this.publicKey
    };
  }

  /**
   * Get wallet info as string
   * @returns {string} - Wallet address
   */
  toString() {
    return this.address;
  }
}

/**
 * Utility function to convert buffer to hex string
 * @param {Buffer|Uint8Array} buffer - Buffer to convert
 * @returns {string} - Hex string with 0x prefix
 */
function bufferToHex(buffer) {
  return "0x" + Buffer.from(buffer).toString("hex");
}

/**
 * Utility function to convert hex string to buffer
 * @param {string} hex - Hex string (with or without 0x prefix)
 * @returns {Uint8Array} - Buffer
 */
function hexToBuffer(hex) {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(cleanHex, 'hex'));
}

/**
 * Generate a new keypair from mnemonic (standalone function)
 * @param {string} mnemonic - BIP39 mnemonic phrase
 * @returns {Promise<object>} - Object containing address, keys, and raw keys
 */
async function generateKeypair(mnemonic) {
  const wallet = await SLHWallet.fromMnemonic(mnemonic);
  return {
    address: wallet.address,
    privateKey: wallet.privateKey,
    publicKey: wallet.publicKey,
    privateKeyRaw: wallet.privateKeyRaw,
    publicKeyRaw: wallet.publicKeyRaw,
  };
}

// Export the class and utility functions
export { SLHWallet, generateKeypair, bufferToHex, hexToBuffer };

// Example usage:
/*
async function example() {
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  
  try {
    // Using the class method (recommended)
    const wallet = await SLHWallet.fromMnemonic(mnemonic);
    console.log('Wallet Address:', wallet.address);
    console.log('Public Key:', wallet.publicKey);
    
    // Sign a message
    const message = "Hello, post-quantum world!";
    const signature = await wallet.signMessage(message);
    console.log('Signature:', signature);
    
    // Verify signature
    const isValid = SLHWallet.verifySignature(message, signature, wallet.publicKeyRaw);
    console.log('Signature valid:', isValid);
    
    // Using the standalone function
    const keypair = await generateKeypair(mnemonic);
    console.log('Generated keypair:', keypair);
    
  } catch (error) {
    console.error('Error:', error.message);
  }
}
*/