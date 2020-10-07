# protect
  
  <a href="https://flutter.io">  
    <img src="https://img.shields.io/badge/Platform-Flutter-yellow.svg"  
      alt="Platform" />  
  </a> 
   <a href="https://pub.dartlang.org/packages/protect">  
    <img src="https://img.shields.io/pub/v/protect.svg"  
      alt="Pub Package" />  
  </a>
   <a href="https://opensource.org/licenses/MIT">  
    <img src="https://img.shields.io/badge/License-MIT-red.svg"  
      alt="License: MIT" />  
  </a>  
   <a href="https://www.paypal.me/kawal7415">  
    <img src="https://img.shields.io/badge/Donate-PayPal-green.svg"  
      alt="Donate" />  
  </a>
   <a href="https://github.com/justkawal/protect/issues">  
    <img src="https://img.shields.io/github/issues/justkawal/protect"  
      alt="Issue" />  
  </a> 
   <a href="https://github.com/justkawal/protect/network">  
    <img src="https://img.shields.io/github/forks/justkawal/protect"  
      alt="Forks" />  
  </a> 
   <a href="https://github.com/justkawal/protect/stargazers">  
    <img src="https://img.shields.io/github/stars/justkawal/protect"  
      alt="Stars" />  
  </a>
  <br>
  <br>
 
 [Protect](https://www.pub.dev/packages/protect) is a flutter and dart library for applying and removing password protection on excel files.



# Table of Contents
  - [Installing](#lets-get-started)
  - [Usage](#usage)
    * [Imports](#imports)
    * [Read xlsx file](#read-xlsx-file)
    * [Read xlsx file from Asset Folder](#read-xlsx-from-flutters-asset-folder)
    * [Apply password on xlsx file](#create-new-xlsx-file)
  - [Donate (Be the First one)](#donate-be-the-first-one)

# Lets Get Started

### 1. Depend on it
Add this to your package's `pubspec.yaml` file:

```yaml
dependencies:
  protect: ^0.0.1
```

### 2. Install it

You can install packages from the command line:

with `pub`:

```css
$  pub get
```

with `Flutter`:

```css
$  flutter packages get
```

### 3. Import it

Now in your `Dart` code, you can use: 

````dart
    import 'package:protect/protect.dart';
````

# Usage

### Imports

````dart
    import 'dart:io';
    import 'package:protect/protect.dart';
    
````

### Read XLSX File

````dart
    var file = "Path_to_pre_existing_Excel_File/excel_file.xlsx";
    var unprotectedExcelBytes = await File(file).readAsBytes();
    or
  //var protectedExcelBytes = await File(file).readAsBytes();
    
````

### Read XLSX from Flutter's Asset Folder

````dart
    import 'package:flutter/services.dart' show ByteData, rootBundle;
    
    /* Your blah blah code here */
    
    ByteData data = await rootBundle.load("assets/existing_excel_file.xlsx");
    var bytes = data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    var unprotectedExcelBytes = await File(file).readAsBytes();
    or
  //var protectedExcelBytes = await File(file).readAsBytes();
    
````

### Apply password protection on XLSX File
    
````dart  
  ///
  /// Applying password protection
  /// where `unprotectedExcelBytes` is Uint8List
  ///
  ProtectResponse encryptedResponse = await Protect.encryptUint8List(unprotectedExcelBytes, 'contact@kawal.dev');

  var data;
  if (encryptedResponse.isDataValid) {
    data = encryptedResponse.processedBytes;
  } else {
    print('Excel file used for applying password over it is corrupted');
  }
    
````

### Remove password protection on XLSX File
    
````dart  
  ///
  /// Applying password protection 
  /// where `protectedExcelBytes` is Uint8List
  ///
  ProtectResponse decryptedResponse = await Protect.decryptUint8List(protectedExcelBytes, 'contact@kawal.dev');
  
  var data;
  if (decryptedResponse.isDataValid) {
    data = decryptedResponse.processedBytes;
  } else {
    print('Either password is wrong for opening the excel file or the Excel file is corrupted');
  }
````
   
 ### Saving XLSX File
 
 ````dart
  // Save the Changes in file
  
  var outputPath = '/Users/kawal/Desktop/form_encrypted_file.xlsx';
  await File(outputPath)
    ..create(recursive: true)
    ..writeAsBytes(data);
    
````


#### Also checkout our other libraries: 
  - Excel **··················**>  [Excel](https://www.github.com/justkawal/excel)
  - Text Animations **··**>  [AnimatedText](https://www.github.com/justkawal/animated_text)
  - Translations **········**>  [Arb Translator](https://www.github.com/justkawal/arb_translator)


### Donate (Be the First one)
  - [Paypal](https://www.paypal.me/kawal7415)
