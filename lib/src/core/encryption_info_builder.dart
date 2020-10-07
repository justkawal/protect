part of protect;

Uint8List _buildEncryptionInfo(encryptionInfo) {
  var xmlEncryptionNode = XmlElement(
    name: 'encryption',
    attributes: [
      XmlAttribute(
          'xmlns', 'http://schemas.microsoft.com/office/2006/encryption'),
      XmlAttribute('xmlns:p',
          'http://schemas.microsoft.com/office/2006/keyEncryptor/password'),
      XmlAttribute('xmlns:c',
          'http://schemas.microsoft.com/office/2006/keyEncryptor/certificate'),
    ],
    children: [
      XmlElement(
        name: 'keyData',
        attributes: [
          XmlAttribute(
              'saltSize', '${encryptionInfo['package']['saltValue'].length}'),
          XmlAttribute(
              'blockSize', '${encryptionInfo['package']['blockSize']}'),
          XmlAttribute('keyBits', '${encryptionInfo['package']['keyBits']}'),
          XmlAttribute('hashSize', '${encryptionInfo['package']['hashSize']}'),
          XmlAttribute('cipherAlgorithm',
              '${encryptionInfo['package']['cipherAlgorithm']}'),
          XmlAttribute('cipherChaining',
              '${encryptionInfo['package']['cipherChaining']}'),
          XmlAttribute(
              'hashAlgorithm', '${encryptionInfo['package']['hashAlgorithm']}'),
          XmlAttribute('saltValue',
              base64.encode(encryptionInfo['package']['saltValue'])),
        ],
      ),
      XmlElement(
        name: 'dataIntegrity',
        attributes: [
          XmlAttribute(
              'encryptedHmacKey',
              base64
                  .encode(encryptionInfo['dataIntegrity']['encryptedHmacKey'])),
          XmlAttribute(
              'encryptedHmacValue',
              base64.encode(
                  encryptionInfo['dataIntegrity']['encryptedHmacValue'])),
        ],
      ),
      XmlElement(
        name: 'keyEncryptors',
        children: [
          XmlElement(
            name: 'keyEncryptor',
            attributes: [
              XmlAttribute('uri',
                  'http://schemas.microsoft.com/office/2006/keyEncryptor/password')
            ],
            children: [
              XmlElement(
                name: 'p:encryptedKey ',
                attributes: [
                  XmlAttribute(
                      'spinCount', '${encryptionInfo['key']['spinCount']}'),
                  XmlAttribute('saltSize',
                      '${encryptionInfo['key']['saltValue'].length}'),
                  XmlAttribute(
                      'blockSize', '${encryptionInfo['key']['blockSize']}'),
                  XmlAttribute(
                      'keyBits', '${encryptionInfo['key']['keyBits']}'),
                  XmlAttribute(
                      'hashSize', '${encryptionInfo['key']['hashSize']}'),
                  XmlAttribute('cipherAlgorithm',
                      '${encryptionInfo['key']['cipherAlgorithm']}'),
                  XmlAttribute('cipherChaining',
                      '${encryptionInfo['key']['cipherChaining']}'),
                  XmlAttribute('hashAlgorithm',
                      '${encryptionInfo['key']['hashAlgorithm']}'),
                  XmlAttribute('saltValue',
                      base64.encode(encryptionInfo['key']['saltValue'])),
                  XmlAttribute(
                      'encryptedVerifierHashInput',
                      base64.encode(
                          encryptionInfo['key']['encryptedVerifierHashInput'])),
                  XmlAttribute(
                      'encryptedVerifierHashValue',
                      base64.encode(
                          encryptionInfo['key']['encryptedVerifierHashValue'])),
                  XmlAttribute(
                      'encryptedKeyValue',
                      base64
                          .encode(encryptionInfo['key']['encryptedKeyValue'])),
                ],
              ),
            ],
          ),
        ],
      ),
    ],
  );
  var n = XmlDocument.fromString(
          '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
              xmlEncryptionNode.toString())
      .toFormattedString();

  var byte = [
    _ENCRYPTION_INFO_PREFIX,
    utf8.encode(n),
  ];

  return Uint8List.fromList(toBuffer(byte));
}
