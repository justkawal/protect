part of protect;

int zeroFillRightShift(int n, int amount) {
  return (n & 0xffffffff) >> amount;
}

int readUInt8(List<int> b, int idx) {
  return b[idx];
}

int readUInt16LE(List<int> b, int idx) {
  return b[idx + 1] * (1 << 8) + b[idx];
}

int readInt16LE(List<int> b, int idx) {
  var u = b[idx + 1] * (1 << 8) + b[idx];
  return (u < 0x8000) ? u : (0xffff - u + 1) * -1;
}

int readUInt32LE(List<int> b, int idx) {
  return b[idx + 3] * (1 << 24) +
      (b[idx + 2] << 16) +
      (b[idx + 1] << 8) +
      b[idx];
}

int readInt32LE(List<int> b, int idx) {
  var k = (b[idx + 3] << 24) + (b[idx + 2] << 16) + (b[idx + 1] << 8) + b[idx];
  return BigInt.from(k).toSigned(32).toInt();
}

void writeUInt32LE(List<int> b, int val, int idx) {
  b[idx] = (val & 0xFF);
  b[idx + 1] = (zeroFillRightShift(val, 8) & 0xFF);
  b[idx + 2] = (zeroFillRightShift(val, 16) & 0xFF);
  b[idx + 3] = (zeroFillRightShift(val, 24) & 0xFF);
}

void writeInt32LE(List<int> b, int val, int idx) {
  b[idx] = (val & 0xFF);
  b[idx + 1] = ((val >> 8) & 0xFF);
  b[idx + 2] = ((val >> 16) & 0xFF);
  b[idx + 3] = ((val >> 24) & 0xFF);
}

String hexlify(List<int> b, int s, int l) {
  var ss = <String>[];
  for (int i = s; i < s + l; ++i) {
    ss.add(('0' + b[i].toRadixString(16)).slice(-2));
  }
  return ss.join('');
}
/* 
List<int> newRawBuf(len) {
  return List<int>(len);
}
 */
/* List<int> s2a(String s) {
  return s.split('').map((e) => e.codeUnitAt(0) & 0xff);
} */

List<int> toBuffer(List<List<int>> bufs) {
  return List<int>.from(bufs.expand((element) => element).toList());
}

String utf16le(List<int> b, int s, int e) {
  var ss = <String>[];
  for (int i = s; i < e; i += 2) {
    ss.add(String.fromCharCode(readUInt16LE(b, i)));
  }
  return ss.join('').replaceAll(_chr0, '');
}
/* 
List<int> bconcat(List<List<int>> bufs) {
  return toBuffer(bufs);
} */

Uint8List _hmac(Uint8List key, Uint8List buffers) {
  var hmacSha256 = Hmac(sha512, key); // HMAC-SHA256
  var digest = hmacSha256.convert(buffers);
  return Uint8List.fromList(digest.bytes);
}

Uint8List _cryptPackage(
    bool encrypt,
    //String cipherAlgorithm,
    //String cipherChaining,
    //String hashAlgorithm,
    int blockSize,
    Uint8List saltValue,
    Uint8List key,
    Uint8List input) {
  // The first 8 bytes is supposed to be the length, but it seems like it is really the length - 4..
  List<Uint8List> outputChunks = List<Uint8List>();
  int offset = encrypt ? 0 : _PACKAGE_OFFSET;

  // The package is encoded in chunks. Encrypt/decrypt each and concat.
  int i = 0, start = 0, end = 0;
  while (end < input.length) {
    start = end;
    end = start + _PACKAGE_ENCRYPTION_CHUNK_SIZE;
    if (end > input.length) {
      end = input.length;
    }

    // Grab the next chunk
    Uint8List inputChunk =
        input.sublist(start + offset, end + (end >= input.length ? 0 : offset));

    // Pad the chunk if it is not an integer multiple of the block size
    int remainder = inputChunk.length % blockSize;
    if (remainder != 0) {
      var myBytes = [inputChunk, Uint8List(blockSize - remainder)];
      inputChunk = Uint8List.fromList(toBuffer(myBytes));
    }

    // Create the initialization vector
    Uint8List iv = _createIV(saltValue, blockSize, i);

    // Encrypt/decrypt the chunk and add it to the array
    Uint8List outputChunk = _crypt(encrypt, key, iv, inputChunk);
    outputChunks.add(outputChunk);
    i++;
  }

  // Concat all of the output chunks.
  var output = Uint8List.fromList(toBuffer(outputChunks));

  if (encrypt) {
    // Put the length of the package in the first 8 bytes
    var myBytes = [_int32bytes(input.length, size: _PACKAGE_OFFSET), output];
    output = Uint8List.fromList(toBuffer(myBytes));
  } else {
    // Truncate the buffer to the size in the prefix
    int length = input.buffer.asUint32List()[0];
    output = output.sublist(0, length);
  }

  return output;
}

Uint8List _createIV(Uint8List saltValue, int blockSize, dynamic blockKey) {
  // Create the block key from the current index
  var blockKey1;
  if (blockKey.runtimeType is int || blockKey is int) {
    blockKey1 = _int32bytes(blockKey);
  } else {
    blockKey1 = List<int>.from(blockKey);
  }

  // Create the initialization vector by hashing the salt with the block key.
  // Truncate or pad as needed to meet the block size.
  Uint8List iv = _hash(saltValue, blockKey1);
  if (iv.length < blockSize) {
    var tmp = Uint8List(blockSize).buffer.asUint8List();
    tmp.fillRange(0, blockSize, 0x36);
    tmp.replaceRange(0, iv.length, iv);
    iv = tmp;
  } else if (iv.length > blockSize) {
    iv = iv.sublist(0, blockSize);
  }

  return iv;
}

Uint8List _convertPasswordToKey(String password, Uint8List saltValue,
    int spinCount, int keyBits, Uint8List blockKey) {
  List<int> key = encodeUtf16le(password);

  key = _hash(saltValue, key);
  spinCount.assertNonNull;

  for (int i = 0; i < spinCount; i++) {
    List<int> iteratorBytes = _int32bytes(i);
    key = _hash(iteratorBytes, key);
  }
  key = _hash(key, blockKey);

  // Truncate or pad as needed to get to length of keyBits
  int keyBytes = (keyBits / 8).round();

  if (key.length < keyBytes) {
    var tmp = Uint8List(keyBytes).buffer.asUint8List();
    tmp.fillRange(0, keyBytes, 0x36);
    tmp.replaceRange(0, key.length, key);
    key = tmp;
  } else if (key.length > keyBytes) {
    key = key.sublist(0, keyBytes);
  }
  return key;
}

Uint8List _crypt(bool encrypt, Uint8List key, Uint8List iv, Uint8List input) {
  var crypt = AesCrypt();
  crypt.aesSetParams(key, iv, AesMode.cbc);
  if (encrypt)
    return crypt.aesEncrypt(input);
  else
    return crypt.aesDecrypt(input);
}

Uint8List _hash(List<int> byte1, List<int> byte2) {
  var myBytes = [byte1, byte2];
  var bytes = Uint8List.fromList(toBuffer(myBytes));
  return sha512.convert(bytes).bytes;
}

Uint8List _int32bytes(int value, {int size: 4}) {
  var buf = Uint8List(size);
  int offset = 0;
  buf[offset++] = value;
  value = zeroFillRightShift(value, 8);
  buf[offset++] = value;
  value = zeroFillRightShift(value, 8);
  buf[offset++] = value;
  value = zeroFillRightShift(value, 8);
  buf[offset++] = value;
  return buf;
}
