part of protect;

class ProtectResponse {
  final bool isDataValid;
  final Uint8List? processedBytes;
  const ProtectResponse({this.processedBytes, required this.isDataValid});
}
