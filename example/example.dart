import 'dart:io';
import 'package:protect/protect.dart';

void main() async {
  ///
  /// Applying password protection
  ///
  var unprotectedBytes =
      await File('/Users/kawal/Desktop/protect/resource/form.xlsx')
          .readAsBytes();
  ProtectResponse protectedResponse =
      await Protect.encryptBytes(unprotectedBytes, 'contact@kawal.dev');

  if (protectedResponse.isDataValid) {
    var outputProtectedFile =
        '/Users/kawal/Desktop/protect/resource/form_encrypted_file.xlsx';
    await File(outputProtectedFile)
      ..create(recursive: true)
      ..writeAsBytes(protectedResponse.processedBytes);
  }

  ///
  /// Removing password protection and getting decryptedBytes from decrypt function
  ///
  var protectedBytesFile = await File(
          '/Users/kawal/Desktop/protect/resource/form_encrypted_file.xlsx')
      .readAsBytes();
  ProtectResponse unprotectedResponse =
      await Protect.decryptBytes(protectedBytesFile, 'contact@kawal.dev');

  if (unprotectedResponse.isDataValid) {
    var outputUnProtectedFile =
        '/Users/kawal/Desktop/protect/resource/form_decrypted.xlsx';
    await File(outputUnProtectedFile)
      ..create(recursive: true)
      ..writeAsBytes(unprotectedResponse.processedBytes);
  }
}
