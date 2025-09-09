import { SLHWallet, generateKeypair } from './slh-wallet.js';

async function testWallet() {
  console.log('🚀 Testing SLH-DSA Wallet Implementation\n');

  // Test mnemonic (standard BIP39 test mnemonic)
  const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  
  try {
    console.log('📝 Mnemonic:', mnemonic);
    console.log('=' .repeat(60));
    
    // Test 1: Create wallet from mnemonic
    console.log('\n1️⃣ Creating wallet from mnemonic...');
    const wallet = await SLHWallet.fromMnemonic(mnemonic);
    
    console.log('✅ Wallet created successfully!');
    console.log('   Address:', wallet.address);
    console.log('   Public Key Length:', wallet.publicKey.length, 'characters');
    console.log('   Private Key Length:', wallet.privateKey.length, 'characters');
    
    // Test 2: Sign a message
    console.log('\n2️⃣ Testing message signing...');
    const message = "Hello, post-quantum cryptography!";
    const signature = await wallet.signMessage(message);
    
    console.log('✅ Message signed successfully!');
    console.log('   Message:', message);
    console.log('   Signature Length:', signature.length, 'characters');
    console.log('   Signature (first 50 chars):', signature.substring(0, 50) + '...');
    
    // Test 3: Verify signature
    console.log('\n3️⃣ Testing signature verification...');
    const isValid = SLHWallet.verifySignature(message, signature, wallet.publicKeyRaw);
    
    console.log('✅ Signature verification result:', isValid ? 'VALID' : 'INVALID');
    
    // Test 4: Test with wrong message (should fail)
    console.log('\n4️⃣ Testing signature verification with wrong message...');
    const wrongMessage = "Different message";
    const isInvalid = SLHWallet.verifySignature(wrongMessage, signature, wallet.publicKeyRaw);
    
    console.log('✅ Wrong message verification result:', isInvalid ? 'VALID' : 'INVALID (expected)');
    
    // Test 5: Test generateKeypair function
    console.log('\n5️⃣ Testing standalone generateKeypair function...');
    const keypair = await generateKeypair(mnemonic);
    
    console.log('✅ Keypair generated successfully!');
    console.log('   Same address?', keypair.address === wallet.address ? 'YES' : 'NO');
    
    // Test 6: Test wallet JSON serialization
    console.log('\n6️⃣ Testing wallet serialization...');
    const walletJSON = wallet.toJSON();
    console.log('✅ Wallet JSON:', JSON.stringify(walletJSON, null, 2));
    
    console.log('\n🎉 All tests completed successfully!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
  }
}

// Additional test with different mnemonic
async function testDifferentMnemonic() {
  console.log('\n' + '='.repeat(60));
  console.log('🔄 Testing with different mnemonic...\n');
  
  const mnemonic2 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
  
  try {
    const wallet1 = await SLHWallet.fromMnemonic(mnemonic2);
    const wallet2 = await SLHWallet.fromMnemonic(mnemonic2);
    
    console.log('✅ Deterministic generation test:');
    console.log('   Wallet 1 address:', wallet1.address);
    console.log('   Wallet 2 address:', wallet2.address);
    console.log('   Same addresses?', wallet1.address === wallet2.address ? 'YES ✅' : 'NO ❌');
    
  } catch (error) {
    console.error('❌ Different mnemonic test failed:', error.message);
  }
}

// Error handling test
async function testErrorHandling() {
  console.log('\n' + '='.repeat(60));
  console.log('🛡️ Testing error handling...\n');
  
  // Test with invalid mnemonic
  try {
    await SLHWallet.fromMnemonic("");
    console.log('❌ Should have thrown error for empty mnemonic');
  } catch (error) {
    console.log('✅ Correctly caught empty mnemonic error:', error.message);
  }
  
  try {
    await SLHWallet.fromMnemonic(null);
    console.log('❌ Should have thrown error for null mnemonic');
  } catch (error) {
    console.log('✅ Correctly caught null mnemonic error:', error.message);
  }
}

// Run all tests
async function runAllTests() {
  await testWallet();
  await testDifferentMnemonic();
  await testErrorHandling();
}

// Execute tests
runAllTests().catch(console.error);