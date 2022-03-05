part of protect;

ProtectResponse _encrypt(Uint8List data, String password) {
  var packageKey = _Utils.createCryptoRandomUint8List(32);

  final encryptionInfo = {
    'package': {
      'cipherAlgorithm': 'AES',
      'cipherChaining': 'ChainingModeCBC',
      'saltValue': _Utils.createCryptoRandomUint8List(16),
      'hashAlgorithm': 'SHA512',
      'hashSize': 64,
      'blockSize': 16,
      'keyBits': packageKey.length * 8
    },
    'key': {
      'cipherAlgorithm': 'AES',
      'cipherChaining': 'ChainingModeCBC',
      'saltValue': _Utils.createCryptoRandomUint8List(16),
      'hashAlgorithm': 'SHA512',
      'hashSize': 64,
      'blockSize': 16,
      'spinCount': 100000,
      'keyBits': 256,
    }
  };
  var encryptedPackage = _cryptPackage(
      true,
      //encryptionInfo['package']['cipherAlgorithm'],
      //encryptionInfo['package']['cipherChaining'],
      //encryptionInfo['package']['hashAlgorithm'],
      encryptionInfo['package']!['blockSize'] as int,
      encryptionInfo['package']!['saltValue'] as Uint8List,
      packageKey,
      data);

  var hmacKey = _Utils.createCryptoRandomUint8List(64);

  // Then create an initialization vector using the package encryption info and the approassertNonNullate block key.
  var hmacKeyIV = _createIV(
    //encryptionInfo['package']['hashAlgorithm'],
    encryptionInfo['package']!['saltValue'] as Uint8List,
    encryptionInfo['package']!['blockSize'] as int,
    _BLOCK_KEYS['dataIntegrity']['hmacKey'],
  );

  // Use the package key and the IV to encrypt the HMAC key
  var encryptedHmacKey = _crypt(
    true,
    //encryptionInfo['package']['cipherAlgorithm'],
    //encryptionInfo['package']['cipherChaining'],
    packageKey,
    hmacKeyIV,
    hmacKey,
  );

  // Now create the HMAC
  var hmacValue = _hmac(hmacKey, encryptedPackage);

  // Next generate an initialization vector for encrypting the resulting HMAC value.
  var hmacValueIV = _createIV(
    //encryptionInfo['package']['hashAlgorithm'],
    encryptionInfo['package']!['saltValue'] as Uint8List,
    encryptionInfo['package']!['blockSize'] as int,
    _BLOCK_KEYS['dataIntegrity']['hmacValue'],
  );

  // Now encrypt the value
  var encryptedHmacValue = _crypt(
    true,
    //encryptionInfo['package']['cipherAlgorithm'],
    //encryptionInfo['package']['cipherChaining'],
    packageKey,
    hmacValueIV,
    hmacValue,
  );

  // Put the encrypted key and value on the encryption info
  encryptionInfo['dataIntegrity'] = {
    'encryptedHmacKey': encryptedHmacKey,
    'encryptedHmacValue': encryptedHmacValue,
  };

  /* Key Encryption */

  // Convert the password to an encryption key
  var key = _convertPasswordToKey(
    password,
    //encryptionInfo['key']['hashAlgorithm'],
    encryptionInfo['key']!['saltValue'] as Uint8List,
    encryptionInfo['key']!['spinCount'] as int,
    encryptionInfo['key']!['keyBits'] as int,
    _BLOCK_KEYS['key'],
  );

  // Encrypt the package key with the
  encryptionInfo['key']!['encryptedKeyValue'] = _crypt(
    true,
    //encryptionInfo['key']['cipherAlgorithm'],
    //encryptionInfo['key']['cipherChaining'],
    key,
    encryptionInfo['key']!['saltValue'] as Uint8List,
    packageKey,
  );

  /* Verifier hash */

  // Create a random byte array for hashing
  var verifierHashInput = _Utils.createCryptoRandomUint8List(16);

  // Create an encryption key from the password for the input
  var verifierHashInputKey = _convertPasswordToKey(
    password,
    //encryptionInfo.key.hashAlgorithm,
    encryptionInfo['key']!['saltValue'] as Uint8List,
    encryptionInfo['key']!['spinCount'] as int,
    encryptionInfo['key']!['keyBits'] as int,
    _BLOCK_KEYS['verifierHash']['input'],
  );

  // Use the key to encrypt the verifier input
  encryptionInfo['key']!['encryptedVerifierHashInput'] = _crypt(
    true,
    //encryptionInfo['key']['cipherAlgorithm'],
    //encryptionInfo['key']['cipherChaining'],
    verifierHashInputKey,
    encryptionInfo['key']!['saltValue'] as Uint8List,
    verifierHashInput,
  );

  // Create a hash of the input
  var verifierHashValue = _hash([], verifierHashInput);

  // Create an encryption key from the password for the hash
  var verifierHashValueKey = _convertPasswordToKey(
    password,
    // encryptionInfo.key.hashAlgorithm,
    encryptionInfo['key']!['saltValue'] as Uint8List,
    encryptionInfo['key']!['spinCount'] as int,
    encryptionInfo['key']!['keyBits'] as int,
    _BLOCK_KEYS['verifierHash']!['value'],
  );

  // Use the key to encrypt the hash value
  encryptionInfo['key']!['encryptedVerifierHashValue'] = _crypt(
    true,
    //encryptionInfo['key']['cipherAlgorithm'],
    //encryptionInfo['key']['cipherChaining'],
    verifierHashValueKey,
    encryptionInfo['key']!['saltValue'] as Uint8List,
    verifierHashValue,
  );

  var encryptionInfoBuffer = _buildEncryptionInfo(encryptionInfo);

  var protect = _PROTECT();
  var output = protect.protect_new();
  protect.protect_add(output, 'EncryptionInfo', encryptionInfoBuffer);
  protect.protect_add(output, 'EncryptedPackage', encryptedPackage);

  protect.protect_del(output, '\u0001PROTEKT');
  _PROTECTBlob encryptedFileBytes = protect._write(output);
  return ProtectResponse(
      isDataValid: true,
      processedBytes: Uint8List.fromList(encryptedFileBytes.packageValue));
}
