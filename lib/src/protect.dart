part of protect;

class Protect {
  ///
  /// Decyrpts the bytes of the .xlsx file with the [password].
  ///
  static ProtectResponse decryptBytes(List<int> data, String password) {
    assertion(data, password);
    return _decrypt(Uint8List.fromList(data), password);
  }

  ///
  /// Decyrpts the Uint8List of the .xlsx file with the [password].
  ///
  static ProtectResponse decryptUint8List(Uint8List data, String password) {
    assertion(data, password);
    return _decrypt(data, password);
  }

  ///
  /// Encyrpts the bytes of the .xlsx file with the [password].
  ///
  static ProtectResponse encryptBytes(List<int> data, String password) {
    assertion(data, password);
    return _encrypt(Uint8List.fromList(data), password);
  }

  ///
  /// Encyrpts the Uint8List of the .xlsx file with the [password].
  ///
  static ProtectResponse encryptUint8List(Uint8List data, String password) {
    assertion(data, password);
    return _encrypt(data, password);
  }

  static void assertion(Uint8List data, String password) {
    data.assertNonNull;
    password.assertNonNull;
  }
}
