part of protect;

class ProtectResponse {
  final bool isDataValid;
  final Uint8List processedBytes;

  ProtectResponse({this.processedBytes, this.isDataValid});
}
