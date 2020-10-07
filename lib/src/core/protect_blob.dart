part of protect;

class _PROTECTBlob with ListMixin<int> implements List<int> {
  List<int> _list; // = <int>[];
  int l;
  int _length;

  _PROTECTBlob(List<int> _) {
    this._list = List<int>.from(_);
    this._length = this._list.length;
  }

  List<int> get packageValue {
    return this._list;
  }

  @override
  int operator [](int _) {
    if (_ > -1 && _ < length) {
      return this._list[_];
    }
    return null;
  }

  @override
  void operator []=(int i, int v) {
    if (i > -1 && i < length) {
      this._list[i] = v;
    }
  }

  @override
  set length(int l) {
    this._length = l;
  }

  @override
  int get length => this._length;

  dynamic readShift(int size, [String t]) {
    t ??= '';
    var oI, oS, type = 0;
    switch (size) {
      case 1:
        oI = readUInt8(this, this.l);
        break;
      case 2:
        oI = (t != 'i' ? readUInt16LE : readInt16LE)(this, this.l);
        break;
      case 4:
        oI = readInt32LE(this, this.l);
        break;
      case 16:
        type = 2;
        oS = hexlify(this, this.l, size);
    }
    this.l += size;
    if (type == 0) return oI;
    return oS;
  }

  _PROTECTBlob writeShift(int t, dynamic val, [String f]) {
    f ??= 'null';
    var size = 0, i = 0;
    switch (f) {
      case 'hex':
        for (; i < t; ++i) {
          var temp = 0;
          try {
            temp = int.parse(val.toString().substring(2 * i, 2 * i + 2),
                radix: 16);
          } catch (e) {}
          this[this.l++] = temp;
        }
        return this;
      case 'utf16le':
        var end = this.l + t;
        for (i = 0; i < min(val.toString().length, t); ++i) {
          var cc = val.toString().codeUnitAt(i);
          this[this.l++] = cc & 0xff;
          this[this.l++] = cc >> 8;
        }
        while (this.l < end) {
          this[this.l++] = 0;
        }
        return this;
    }
    switch (t) {
      case 1:
        size = 1;
        this[this.l] = val & 0xFF;
        break;
      case 2:
        size = 2;
        this[this.l] = val & 0xFF;
        val = zeroFillRightShift(val, 8);
        this[this.l + 1] = val & 0xFF;
        break;
      case 4:
        size = 4;
        writeUInt32LE(this, val, this.l);
        break;
      case -4:
        size = 4;
        writeInt32LE(this, val, this.l);
        break;
    }
    this.l += size;
    return this;
  }

  void chk(String hexstr, String fld) {
    var m = hexlify(this, this.l, hexstr.length >> 1);
    if (m != hexstr) {
      throw ArgumentError(fld + 'Expected ' + hexstr + ' saw ' + m);
    }
    this.l += hexstr.length >> 1;
  }
}
