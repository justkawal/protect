// ignore_for_file: constant_identifier_names

part of protect;

class ListRange extends IterableBase<int> {
  final List<int> _source;
  final int _offset;
  final int _length;

  ListRange(List<int> source, [int offset = 0, int? length])
      : _source = source,
        _offset = offset,
        _length = (length ?? source.length - offset) {
    if (_offset < 0 || _offset > _source.length) {
      throw RangeError.value(_offset);
    }
    if (_length < 0) {
      throw RangeError.value(_length);
    }
    if (_length + _offset > _source.length) {
      throw RangeError.value(_length + _offset);
    }
  }

  @override
  ListRangeIterator get iterator =>
      _ListRangeIteratorImpl(_source, _offset, _offset + _length);

  @override
  int get length => _length;
}

/// The ListRangeIterator provides more capabilities than a standard iterator,
/// including the ability to get the current position, count remaining items,
/// and move forward/backward within the iterator.
abstract class ListRangeIterator implements Iterator<int> {
  @override
  bool moveNext();
  @override
  int get current;
  int get position;
  void backup([int by]);
  int get remaining;
  void skip([int count]);
}

class _ListRangeIteratorImpl implements ListRangeIterator {
  final List<int> _source;
  int _offset;
  final int _end;

  _ListRangeIteratorImpl(this._source, int offset, this._end)
      : _offset = offset - 1;

  @override
  int get current => _source[_offset];

  @override
  bool moveNext() => ++_offset < _end;

  @override
  int get position => _offset;

  @override
  void backup([int by = 1]) {
    _offset -= by;
  }

  @override
  int get remaining => _end - _offset - 1;

  @override
  void skip([int count = 1]) {
    _offset += count;
  }
}

List<int> encodeUtf16le(String str, [bool writeBOM = false]) {
  var utf16CodeUnits = _stringToUtf16CodeUnits(str);
  var encoding = <int>[];
  //List<int>(/* 2 * utf16CodeUnits.length + (writeBOM ? 2 : 0) */);
  if (writeBOM) {
    encoding.add(UNICODE_UTF_BOM_LO);
    encoding.add(UNICODE_UTF_BOM_HI);
  }
  for (var unit in utf16CodeUnits) {
    encoding.add(unit & UNICODE_BYTE_ZERO_MASK);
    encoding.add((unit & UNICODE_BYTE_ONE_MASK) >> 8);
  }
  return encoding;
}

/// Invalid codepoints or encodings may be substituted with the value U+fffd.
const int UNICODE_REPLACEMENT_CHARACTER_CODEPOINT = 0xfffd;
const int UNICODE_BOM = 0xfeff;
const int UNICODE_UTF_BOM_LO = 0xff;
const int UNICODE_UTF_BOM_HI = 0xfe;

const int UNICODE_BYTE_ZERO_MASK = 0xff;
const int UNICODE_BYTE_ONE_MASK = 0xff00;
const int UNICODE_VALID_RANGE_MAX = 0x10ffff;
const int UNICODE_PLANE_ONE_MAX = 0xffff;
const int UNICODE_UTF16_RESERVED_LO = 0xd800;
const int UNICODE_UTF16_RESERVED_HI = 0xdfff;
const int UNICODE_UTF16_OFFSET = 0x10000;
const int UNICODE_UTF16_SURROGATE_UNIT_0_BASE = 0xd800;
const int UNICODE_UTF16_SURROGATE_UNIT_1_BASE = 0xdc00;
const int UNICODE_UTF16_HI_MASK = 0xffc00;
const int UNICODE_UTF16_LO_MASK = 0x3ff;

/// Encode code points as UTF16 code units.
List<int> codepointsToUtf16CodeUnits(List<int> codepoints,
    [int offset = 0,
    int? length,
    int? replacementCodepoint = UNICODE_REPLACEMENT_CHARACTER_CODEPOINT]) {
  var listRange = ListRange(codepoints, offset, length);
  //var encodedLength = 0;
  for (var value in listRange) {
    if ((value >= 0 && value < UNICODE_UTF16_RESERVED_LO) ||
        (value > UNICODE_UTF16_RESERVED_HI && value <= UNICODE_PLANE_ONE_MAX)) {
      //encodedLength++;
    } else if (value > UNICODE_PLANE_ONE_MAX &&
        value <= UNICODE_VALID_RANGE_MAX) {
      //encodedLength += 2;
    } else {
      //encodedLength++;
    }
  }

  var codeUnitsBuffer = <int>[];

  for (var value in listRange) {
    if ((value >= 0 && value < UNICODE_UTF16_RESERVED_LO) ||
        (value > UNICODE_UTF16_RESERVED_HI && value <= UNICODE_PLANE_ONE_MAX)) {
      codeUnitsBuffer.add(value);
    } else if (value > UNICODE_PLANE_ONE_MAX &&
        value <= UNICODE_VALID_RANGE_MAX) {
      var base = value - UNICODE_UTF16_OFFSET;
      codeUnitsBuffer.add(UNICODE_UTF16_SURROGATE_UNIT_0_BASE +
          ((base & UNICODE_UTF16_HI_MASK) >> 10));
      codeUnitsBuffer.add(
          UNICODE_UTF16_SURROGATE_UNIT_1_BASE + (base & UNICODE_UTF16_LO_MASK));
    } else if (replacementCodepoint != null) {
      codeUnitsBuffer.add(replacementCodepoint);
    } else {
      throw ArgumentError('Invalid encoding');
    }
  }
  return codeUnitsBuffer;
}

List<int> _stringToUtf16CodeUnits(String str) {
  return codepointsToUtf16CodeUnits(str.codeUnits);
}
