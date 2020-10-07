part of protect;

bool isFileNotProtected(Uint8List data) {
  return data.length > 1 && data[0] == 0x50 && data[1] == 0x4b;
}
