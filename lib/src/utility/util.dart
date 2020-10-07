part of protect;

class _Utils {
  static final Random _random = Random.secure();

  static Uint8List createCryptoRandomUint8List([int length = 32]) {
    return Uint8List.fromList(
        List<int>.generate(length, (i) => _random.nextInt(256)));
  }
}
