part of protect;

extension ProtectString on String {
  int toInt() {
    return int.tryParse(this);
  }

  String slice(int start, [int end]) {
    if (start == null) {
      start = 0;
    }

    if (start < 0) {
      start += this.length;
      if (start < 0) {
        start = 0;
      }
    }
    if (start >= this.length) {
      return '';
    }
    if (end == null) {
      end = this.length;
    }
    if (end < 0) {
      end += this.length;
      if (end < 0) {
        end = 0;
      }
    }
    if (end > this.length) {
      end = this.length;
    }
    if (start > end) {
      return '';
    }

    var out = '';
    while (start <= --end) {
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
  List<T> slice(int start, [int end]) {
    if (start == null) {
      start = 0;
    }
    if (start < 0) {
      start += this.length;
      if (start < 0) {
        start = 0;
      }
    }
    if (start >= this.length) {
      return List<T>(0);
    }
    if (end == null) {
      end = this.length;
    }
    if (end < 0) {
      end += this.length;
      if (end < 0) {
        end = 0;
      }
    }
    if (end > this.length) {
      end = this.length;
    }
    if (start > end) {
      return List<T>(0);
    }
    var out = List<T>(end - start);
    while (start <= --end) {
      out[end - start] = this[end];
    }
    return out;
  }

  ///     [Same as in JavaScript]
  ///
  ///     [Negative Indexs are accepted]
  ///
  List<T> splice(int position, [int removeCount, List<T> value]) {
    if (position < 0) {
      position += this.length;
      if (position < 0) {
        position = 0;
      }
    }
    if (position > this.length) {
      position = this.length;
    }

    // start removing
    if (position < this.length) {
      if (removeCount == null) {
        // remove everything after the position
        this.removeRange(position, this.length);
      } else {
        if (removeCount > 0) {
          int temp = 1;
          while (temp <= removeCount && position < this.length) {
            this.removeAt(position);
            temp += 1;
          }
        }
      }
    }

    //start adding
    if (value != null && value.isNotEmpty) {
      List<T> temp = List<T>.from(value);
      while (temp.isNotEmpty) {
        this.insert(position, temp.removeLast());
      }
    }
    return this;
  }

  ///     [Same as in JavaScript]
  ///
  /// appends the [val] in the list
  ///
  void push(T val) {
    this.add(val);
  }

  ///
  /// removes the last element from the list and returns it
  ///
  T pop() {
    if (this.isNotEmpty) {
      return this.removeLast();
    }
    return null;
  }
}

extension AssertionString on String {
  void get assertNonNull {
    assert(this != null);
  }
}

extension AssertionInt on int {
  void get assertNonNull {
    assert(this != null);
  }
}

extension AssertionUint8List on Uint8List {
  void get assertNonNull {
    assert(this != null);
  }
}

extension AssertionXmlElement on XmlElement {
  void get assertNonNull {
    assert(this != null);
  }
}
