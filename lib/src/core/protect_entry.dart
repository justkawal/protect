part of protect;

class _PROTECTEntry {
  /// Variables
  String? name, storage, clsid, ctype;
  _PROTECTBlob? _content;
  DateTime? ct, mt;
  int? color, type, state, start, size, L, R, C;

  _PROTECTBlob? get content => _content;

  set content(_PROTECTBlob? blob) {
    if (blob != null) {
      _content = _PROTECTBlob(List<int>.from(blob.packageValue));
    }
  }
}
