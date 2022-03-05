part of protect;

// ignore_for_file: non_constant_identifier_names, constant_identifier_names
final _ENCRYPTION_INFO_PREFIX = Uint8List.fromList([
  0x04,
  0x00,
  0x04,
  0x00,
  0x40,
  0x00,
  0x00,
  0x00
]); // First 4 bytes are the version number, second 4 bytes are reserved.

const _keyDataList = [
  'saltSize',
  'blockSize',
  'keyBits',
  'hashSize',
  'cipherAlgorithm',
  'cipherChaining',
  'hashAlgorithm',
  'saltValue',
];
const _dataIntegrityList = [
  'encryptedHmacKey',
  'encryptedHmacValue',
];

const _encryptedKeyList = [
  'spinCount',
  'saltSize',
  'blockSize',
  'keyBits',
  'hashSize',
  'cipherAlgorithm',
  'cipherChaining',
  'hashAlgorithm',
  'saltValue',
  'encryptedVerifierHashInput',
  'encryptedVerifierHashValue',
  'encryptedKeyValue',
];
const _PACKAGE_ENCRYPTION_CHUNK_SIZE = 4096;
const _PACKAGE_OFFSET = 8; // First 8 bytes are the size of the stream

final Map<String, dynamic> _BLOCK_KEYS = {
  'dataIntegrity': {
    'hmacKey':
        Uint8List.fromList([0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6]),
    'hmacValue':
        Uint8List.fromList([0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33]),
  },
  'key': Uint8List.fromList([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6]),
  'verifierHash': {
    'input':
        Uint8List.fromList([0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79]),
    'value':
        Uint8List.fromList([0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e])
  }
};
const _chr0 = r'\u0000', _chr1 = r'[\u0001-\u0006]';
const _MSSZ = 64;
const _ENDOFCHAIN = -2;
const _HEADER_SIGNATURE = 'd0cf11e0a1b11ae1';
const _HEADER_SIG = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const _HEADER_CLSID = '00000000000000000000000000000000';
const _DIFSECT = -4;
const _FATSECT = -3;
