part of protect;

class _PROTECTBlob with ListMixin<int> implements List<int> {
  List<int> _list = <int>[];
  late int l;
  late int _length;

  _PROTECTBlob(List<int> _) {
    _list = List<int>.from(_);
    _length = _list.length;
  }

  List<int> get packageValue {
    return _list;
  }

  @override
  int operator [](int index) {
    return _list[index];
  }

  @override
  void operator []=(int index, int value) {
    _list[index] = value;
  }

  @override
  set length(int l) {
    _length = l;
  }

  @override
  int get length => _length;

  dynamic readShift(int size, [String? t]) {
    t ??= '';
    var oI, oS, type = 0;
    switch (size) {
      case 1:
        oI = readUInt8(this, l);
        break;
      case 2:
        oI = (t != 'i' ? readUInt16LE : readInt16LE)(this, l);
        break;
      case 4:
        oI = readInt32LE(this, l);
        break;
      case 16:
        type = 2;
        oS = hexlify(this, l, size);
    }
    l += size;
    if (type == 0) {
      return oI;
    }
    return oS;
  }

  _PROTECTBlob writeShift(int to, dynamic val, [String? fremType]) {
    var size = 0, i = 0;
    if (fremType != null) {
      switch (fremType) {
        case 'hex':
          for (; i < to; ++i) {
            var temp = 0;
            try {
              temp = int.parse(val.toString().substring(2 * i, 2 * i + 2),
                  radix: 16);
            } catch (e) {}
            this[l++] = temp;
          }
          return this;
        case 'utf16le':
          var end = l + to;
          for (i = 0; i < min(val.toString().length, to); ++i) {
            var cc = val.toString().codeUnitAt(i);
            this[l++] = cc & 0xff;
            this[l++] = cc >> 8;
          }
          while (l < end) {
            this[l++] = 0;
          }
          return this;
      }
    }
    switch (to) {
      case 1:
        size = 1;
        this[l] = val & 0xFF;
        break;
      case 2:
        size = 2;
        this[l] = val & 0xFF;
        val = zeroFillRightShift(val, 8);
        this[l + 1] = val & 0xFF;
        break;
      case 4:
        size = 4;
        writeUInt32LE(this, val, l);
        break;
      case -4:
        size = 4;
        writeInt32LE(this, val, l);
        break;
    }
    l += size;
    return this;
  }

  void chk(String hexstr, String fld) {
    var m = hexlify(this, l, hexstr.length >> 1);
    if (m != hexstr) {
      throw ArgumentError(fld + 'Expected ' + hexstr + ' saw ' + m);
    }
    l += hexstr.length >> 1;
  }
}
