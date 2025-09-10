import { mnemonicToEntropy } from "bip39";
import { shake256 } from "@noble/hashes/sha3";
import { keccak256 } from "ethereum-cryptography/keccak";
import * as slh from "@noble/post-quantum/slh-dsa";
import { Buffer } from "buffer";
import axios from 'axios';
import { BigNumber } from '@ethersproject/bignumber';
import rlp from "rlp";


/**
 * SLH-DSA Wallet class that replaces ethers Wallet.fromMnemonic functionality
 * but uses post-quantum SLH-DSA keypairs instead of ECDSA
 */
class SLHWallet {
  constructor(address, privateKey, publicKey, privateKeyRaw, publicKeyRaw, index) {
    this.address = address;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.privateKeyRaw = privateKeyRaw;
    this.publicKeyRaw = publicKeyRaw;
    this.index = index;
  }

  /**
   * Create a wallet from mnemonic using SLH-DSA keypair derivation
   * @param {string} mnemonic - BIP39 mnemonic phrase
   * @param {number} index - Account index (default: 0)
   * @returns {SLHWallet} - Wallet instance with SLH-DSA derived address
   */
  static fromMnemonic(mnemonic, index = 0) {
    try {
      // Validate inputs
      // if (!mnemonic || typeof mnemonic !== 'string') {
      //   throw new Error('Invalid mnemonic: must be a non-empty string');
      // }
      
      // if (typeof index !== 'number' || index < 0 || !Number.isInteger(index)) {
      //   throw new Error('Invalid index: must be a non-negative integer');
      // }

      // Convert mnemonic to entropy
      const entropy = Buffer.from(mnemonicToEntropy(mnemonic), "hex");
      let seed96;
      
      // Create derivation-specific entropy by combining original entropy with index
      if(index>0)
      {
        const indexBuffer = Buffer.allocUnsafe(4);
        indexBuffer.writeUInt32BE(index, 0);
        const combinedEntropy = Buffer.concat([entropy, indexBuffer]);
        seed96 = shake256.create({ dkLen: 96 }).update(combinedEntropy).digest();
      }
      else
      {
      // Generate 96-byte seed using SHAKE256 with derivation-specific entropy
        seed96 = shake256.create({ dkLen: 96 }).update(entropy).digest();
      }
      
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

      console.log(address.toLowerCase());
      // Return new wallet instance
      return new SLHWallet(
        address.toLowerCase(),
        bufferToHex(keys.secretKey),
        bufferToHex(originalPublicKey),
        keys.secretKey,
        keys.publicKey,
        index
      );

    } catch (error) {
      throw new Error(`Failed to create wallet from mnemonic: ${error.message}`);
    }
  }

  /**
     * Get nonce from network
     * @returns {Promise<number>} - Current nonce for the address
     */
    async getNonce() {
        if (!this.provider) {
            throw new Error('No provider connected');
        }

        try {
            const response = await axios.post(this.provider.connection.url, {
                jsonrpc: "2.0",
                method: "eth_getTransactionCount",
                params: [this.address, "latest"],
                id: 1,
            });

            if (response.data.error) {
                throw new Error(response.data.error.message);
            }

            return parseInt(response.data.result, 16);
        } catch (error) {
            console.error("Error getting nonce:", error);
            throw new Error("Failed to get nonce from network");
        }
    }

    /**
     * Get gas price from network
     * @returns {BigNumber} - Current gas price in wei
     */
    async getGasPrice() {
        if (!this.provider) {
            throw new Error('No provider connected');
        }

        try {
            const response = await axios.post(this.provider.connection.url, {
                jsonrpc: "2.0",
                method: "eth_gasPrice",
                params: [],
                id: 1,
            });

            if (response.data.error) {
                throw new Error(response.data.error.message);
            }

            return BigNumber.from(response.data.result);
        } catch (error) {
            console.error("Error getting gas price:", error);
            throw new Error("Failed to get gas price from network");
        }
    }

    /**
     * Estimate gas limit for a transaction
     * @param {string} to - Recipient address
     * @param {string|number} valueWei - Amount to send in wei
     * @returns {Promise<number>} - Estimated gas limit
     */
    async estimateGas(to, valueWei) {
        if (!this.provider) {
            throw new Error('No provider connected');
        }

        try {
            const response = await axios.post(this.provider.connection.url, {
                jsonrpc: "2.0",
                method: "eth_estimateGas",
                params: [
                    {
                        from: this.address,
                        to: to,
                        value: typeof valueWei === 'string' ? valueWei : `0x${valueWei.toString(16)}`,
                        data: "0x",
                    },
                ],
                id: 1,
            });

            if (response.data.error) {
                throw new Error(response.data.error.message);
            }

            return parseInt(response.data.result, 16);
        } catch (error) {
            console.error("Error getting gas limit:", error);
            // Return a default gas limit if estimation fails
            return 21000; // Default gas limit for simple transfers
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
      console.log(bufferToHex(signature));
      return bufferToHex(signature);
    } catch (error) {
      throw new Error(`Failed to sign message: ${error.message}`);
    }
  }

  /**
   * PLACEHOLDER: Sign a transaction (NOT COMPATIBLE WITH ETHEREUM)
   * This method exists to maintain API compatibility but will not work with Ethereum networks
   * @param {object} transaction - Transaction object
   * @returns {Promise<string>} - "Signed" transaction (placeholder)
   */
  /**
 * Sign a transaction using SLH-DSA
 * @param {object} transaction - Transaction object
 * @returns {Promise<string>} - Signed transaction hex string
 */
async signTransaction(transaction) {
    try {
        // Format transaction fields
        const unsignedTxFields = [
            transaction.nonce ? 
                BigNumber.from(transaction.nonce)._hex : '0x',
            transaction.gasPrice ? 
                BigNumber.from(transaction.gasPrice)._hex : '0x',
            transaction.gasLimit ? 
                BigNumber.from(transaction.gasLimit)._hex : '0x',
            transaction.to || '0x',
            transaction.value ? 
                BigNumber.from(transaction.value)._hex : '0x',
            transaction.data || '0x',
            transaction.chainId ? 
                BigNumber.from(transaction.chainId)._hex : '0x',
            '0x',
            '0x'
        ];

        // RLP encode and hash
        const rlpEncoded = rlp.encode(unsignedTxFields);
        const msgHash = keccak256(rlpEncoded);

        // Sign using SLH-DSA
        const signature = slh.slh_dsa_shake_256f.sign(
            this.privateKeyRaw,
            msgHash
        );

        // Verify signature length
        if (signature.length !== 49856) {
            throw new Error(`Invalid signature length: ${signature.length}`);
        }

        // Convert signature to hex
        const signatureHex = Buffer.from(signature).toString('hex');
        
        // Get public key without 0x prefix
        const publicKey = this.publicKey.replace('0x', '');

        // Return combined signature + public key
        return '0x' + signatureHex + publicKey;

    } catch (error) {
        console.error("Transaction signing error:", error);
        throw new Error(`Failed to sign transaction: ${error.message}`);
    }
}
  /**
   * Connect to a provider (placeholder for compatibility)
   * @param {object} provider - Ethereum provider
   * @returns {SLHWallet} - This wallet instance
   */
  connect(provider) {
    this.provider = provider;
    return this;
  }

  // /**
  //  * Get transaction count (placeholder - uses provider if available)
  //  * @returns {Promise<number>} - Transaction count
  //  */
  // async getTransactionCount() {
  //   if (this.provider) {
  //     try {
  //       return await this.provider.getTransactionCount(this.address);
  //     } catch (error) {
  //       console.warn('Failed to get transaction count from provider:', error.message);
  //     }
  //   }
  //   return 0;
  // }

  /**
   * Get balance (placeholder - uses provider if available)
   * @returns {Promise<string>} - Balance in wei
   */
  async getBalance() {
    if (this.provider) {
      try {
        return await this.provider.getBalance(this.address);
      } catch (error) {
        console.warn('Failed to get balance from provider:', error.message);
      }
    }
    return "0";
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
      publicKey: this.publicKey,
      index: this.index
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

// Export the class and utility functions
export { SLHWallet, bufferToHex, hexToBuffer };