import 'dart:io';
import 'package:protect/protect.dart';

void main() async {
  ///
  /// Applying password protection
  ///
  var unprotectedBytes =
      await File('/path_to_excel_file/protect/resource/form.xlsx')
          .readAsBytes();
  ProtectResponse protectedResponse =
      Protect.encryptBytes(unprotectedBytes, 'contact@kawal.dev');

  if (protectedResponse.isDataValid) {
    var outputProtectedFile =
        '/path_to_excel_file/protect/resource/form_encrypted_file.xlsx';
    File(outputProtectedFile)
      ..create(recursive: true)
      ..writeAsBytes(protectedResponse.processedBytes!).then((_) async {
        ///
        /// Removing password protection and getting decryptedBytes from decrypt function
        ///
        var protectedBytesFile = await File(
                '/path_to_excel_file/protect/resource/form_encrypted_file.xlsx')
            .readAsBytes();
        ProtectResponse unprotectedResponse =
            Protect.decryptBytes(protectedBytesFile, 'contact@kawal.dev');

        if (unprotectedResponse.isDataValid) {
          var outputUnProtectedFile =
              '/path_to_excel_file/protect/resource/form_decrypted.xlsx';
          File(outputUnProtectedFile)
            ..create(recursive: true)
            ..writeAsBytes(unprotectedResponse.processedBytes!);
        }
      });
  }
}
