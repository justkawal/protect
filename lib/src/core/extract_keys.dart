part of protect;

Map<String, dynamic> _extractKeys(XmlDocument xml) {
  var result = <String, dynamic>{};
  final keys = xml.getChild('encryption');
  keys.assertNonNull;

  //
  // Extract keyData
  //
  final keyData = keys?.getChild('keyData');
  var keyDataMap = _extractParticularKeys(keyData, _keyDataList, 'keyData');
  result['keyData'] = Map<String, String>.from(keyDataMap);

  //
  // Extract dataIntegrity
  //
  final dataIntegrity = keys?.getChild('dataIntegrity');
  var dataIntegrityMap = _extractParticularKeys(
      dataIntegrity, _dataIntegrityList, 'dataIntegrity');
  result['dataIntegrity'] = Map<String, String>.from(dataIntegrityMap);

  //
  // Extract encryptedKey
  //
  final encryptedKey = keys
      ?.getChild('keyEncryptors')
      ?.getChild('keyEncryptor')
      ?.getChild('p:encryptedKey');
  var encryptedKeyMap =
      _extractParticularKeys(encryptedKey, _encryptedKeyList, 'p:encryptedKey');
  result['p:encryptedKey'] = Map<String, String>.from(encryptedKeyMap);

  return result;
}

Map<String, String> _extractParticularKeys(
    XmlElement? nodeElement, List<String> keys, String key) {
  nodeElement.assertNonNull;

  var keyDataMap = <String, String>{};
  for (var attributeName in keys) {
    var value = nodeElement?.getAttribute(attributeName);
    if (value != null) {
      keyDataMap[attributeName] = value;
    } else {
      throw Exception('Insufficient $key found');
    }
  }
  return Map<String, String>.from(keyDataMap);
}
