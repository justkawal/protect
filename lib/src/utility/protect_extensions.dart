part of protect;

extension ProtectString on String {
  int? toInt() {
    return int.tryParse(this);
  }

  String slice(int? start, [int? end]) {
    start ??= 0;

    if (start < 0) {
      start += length;
      if (start < 0) {
        start = 0;
      }
    }
    if (start >= length) {
      return '';
    }

    end ??= length;

    if (end < 0) {
      end += length;
      if (end < 0) {
        end = 0;
      }
    }
    if (end > length) {
      end = length;
    }
    if (start > end) {
      return '';
    }

    var out = '';
    while (end != null && start <= --end) {
      out = this[end] + out;
    }

    return out;
  }
}

extension ProtectList<T> on List<T> {
  ///
  ///     [Same as in JavaScript]
  ///
  ///     [Negative Indexs are accepted]
  ///
  /// slices the list
  List<T> slice(int? start, [int? end]) {
    start ??= 0;

    if (start < 0) {
      start += length;
      if (start < 0) {
        start = 0;
      }
    }
    if (start >= length) {
      return <T>[];
    }

    end ??= length;

    if (end < 0) {
      end += length;
      if (end < 0) {
        end = 0;
      }
    }
    if (end > length) {
      end = length;
    }
    if (start > end) {
      return <T>[];
    }
    var out = List<T>.filled(end - start, this[0]);
    while (end != null && start <= --end) {
      out[end - start] = this[end];
    }
    return out;
  }

  ///     [Same as in JavaScript]
  ///
  ///     [Negative Indexs are accepted]
  ///
  List<T> splice(int position, [int? removeCount, List<T>? value]) {
    if (position < 0) {
      position += length;
      if (position < 0) {
        position = 0;
      }
    }
    if (position > length) {
      position = length;
    }

    // start removing
    if (position < length) {
      if (removeCount == null) {
        // remove everything after the position
        removeRange(position, length);
      } else {
        if (removeCount > 0) {
          int temp = 1;
          while (temp <= removeCount && position < length) {
            removeAt(position);
            temp += 1;
          }
        }
      }
    }

    //start adding
    if (value != null && value.isNotEmpty) {
      List<T> temp = List<T>.from(value);
      while (temp.isNotEmpty) {
        insert(position, temp.removeLast());
      }
    }
    return this;
  }

  ///     [Same as in JavaScript]
  ///
  /// appends the [val] in the list
  ///
  void push(T val) {
    add(val);
  }

  ///
  /// removes the last element from the list and returns it
  ///
  T? pop() {
    if (isNotEmpty) {
      return removeLast();
    }
    return null;
  }
}

extension AssertionString on String? {
  void get assertNonNull {
    assert(this != null);
  }
}

extension AssertionInt on int? {
  void get assertNonNull {
    assert(this != null);
  }
}

extension AssertionUint8List on Uint8List? {
  void get assertNonNull {
    assert(this != null);
  }
}

extension AssertionXmlElement on XmlElement? {
  void get assertNonNull {
    assert(this != null);
  }
}
