library protect;

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:aes_crypt_null_safe/aes_crypt_null_safe.dart';
import 'package:crypto/crypto.dart';
import 'package:xml_parser/xml_parser.dart';
import 'dart:math';

///
/// utility files
part 'src/utility/utf.dart';
part 'src/utility/util.dart';
part 'src/utility/protect_extensions.dart';
part 'src/utility/methods.dart';
part 'src/core/encryption_info_builder.dart';

///
/// core files
part 'src/core/protect_container.dart';
part 'src/core/protect_entry.dart';
part 'src/core/protect_blob.dart';
part 'src/core/sector_entry.dart';
part 'src/core/sector_list.dart';
part 'src/core/protect_core.dart';
part 'src/core/extract_keys.dart';
part 'src/core/protect_decrypt.dart';
part 'src/core/protect_encrypt.dart';
part 'src/core/check_protection.dart';

///
/// response
part 'src/response/protect_response.dart';

///
/// constants
part 'src/constants/constants.dart';
part 'src/protect.dart';
