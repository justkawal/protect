part of protect;

ProtectResponse _decrypt(Uint8List encryptedBytes, String password) {
  if (encryptedBytes.length < 2) {
    return ProtectResponse(isDataValid: false, processedBytes: encryptedBytes);
  }
  if (isFileNotProtected(encryptedBytes)) {
    /// file is not protected so just return this back
    return ProtectResponse(isDataValid: true, processedBytes: encryptedBytes);
  }
  var protect = _PROTECT();
  var file = protect.parse(encryptedBytes);

  var encryptedPackage, encryptedPackageInfo;
  for (var i = 0; i < file.FileIndex.length; i++) {
    var name = file.FileIndex[i].name.toString();
    if (name.isNotEmpty) {
      var nameSliced = name.substring(0, name.length - 1);
      if (nameSliced == 'EncryptedPackage') {
        encryptedPackage =
            Uint8List.fromList(file.FileIndex[i].content!.packageValue);
      } else if (nameSliced == 'EncryptionInfo') {
        encryptedPackageInfo = file.FileIndex[i].content!.packageValue;
      }
    }
  }
  final encryptionXml = XmlDocument.from(utf8.decode(encryptedPackageInfo))!;

  final encryptionInfo = _extractKeys(encryptionXml);

  // KeyData
  final keyDataBlockSize = int.tryParse(encryptionInfo['keyData']['blockSize']);
  keyDataBlockSize.assertNonNull;
  final keyDataSaltValue =
      base64.decode(encryptionInfo['keyData']['saltValue']);

  // DataIntegrity
  final encryptedHmacKey =
      base64.decode(encryptionInfo['dataIntegrity']['encryptedHmacKey']);
  final encryptedHmacValue =
      base64.decode(encryptionInfo['dataIntegrity']['encryptedHmacValue']);

  // p:encryptedKey
  final encryptedKeySpinCount =
      int.tryParse(encryptionInfo['p:encryptedKey']['spinCount']);
  encryptedKeySpinCount.assertNonNull;

  final encryptedKeyKeyBits =
      int.tryParse(encryptionInfo['p:encryptedKey']['keyBits']);
  encryptedKeyKeyBits.assertNonNull;
  final encryptedKeySaltValue =
      base64.decode(encryptionInfo['p:encryptedKey']['saltValue']);
  final encryptedKeyEncryptedKeyValue =
      base64.decode(encryptionInfo['p:encryptedKey']['encryptedKeyValue']);

  /// create key from the password
  var key = _convertPasswordToKey(
    password,
    encryptedKeySaltValue,
    encryptedKeySpinCount!,
    encryptedKeyKeyBits!,
    _BLOCK_KEYS['key'],
  );

  // get package Key
  var packageKey = _crypt(
    false,
    key,
    encryptedKeySaltValue,
    encryptedKeyEncryptedKeyValue,
  );

  /// Verify the Hmac for data integrity
  ///
  /// create hmac iv
  var hmacKeyIV = _createIV(
    keyDataSaltValue,
    keyDataBlockSize!,
    _BLOCK_KEYS['dataIntegrity']['hmacKey'],
  );

  // Use the package key and the IV to decrypt the encrypted HMAC key
  var decryptedHmacKey = _crypt(
    false,
    packageKey,
    hmacKeyIV,
    encryptedHmacKey,
  );

  // Now create the HMAC
  var originalHmacValue = _hmac(decryptedHmacKey, encryptedPackage);

  // Next generate an initialization vector for encrypting the resulting HMAC value.
  var hmacValueIV = _createIV(
    keyDataSaltValue,
    keyDataBlockSize,
    _BLOCK_KEYS['dataIntegrity']['hmacValue'],
  );

  // Now encrypt the value
  var decryptedHmacValue = _crypt(
    false,
    packageKey,
    hmacValueIV,
    encryptedHmacValue,
  );
  bool isDataCorrupted = false;
  /* 
  var itr1 = originalHmacValue.iterator;
  var itr2 = decryptedHmacValue.iterator;
  while (itr1.moveNext() && itr2.moveNext()) {
    if (itr1.current != itr2.current) {
      isDataCorrupted = true;
      break;
    }
  } */

  if (originalHmacValue.length == decryptedHmacValue.length) {
    for (var i = 0; i < originalHmacValue.length; i++) {
      if (originalHmacValue[i] != decryptedHmacValue[i]) {
        isDataCorrupted = true;
        break;
      }
    }
  } else {
    isDataCorrupted = true;
  }
  if (isDataCorrupted) {
    return const ProtectResponse(isDataValid: false);
  }

  var dec = Uint8List.fromList(encryptedPackage);
  var decrypted = _cryptPackage(
    false,
    keyDataBlockSize,
    keyDataSaltValue,
    packageKey,
    dec,
  );

  return ProtectResponse(processedBytes: decrypted, isDataValid: true);
}
