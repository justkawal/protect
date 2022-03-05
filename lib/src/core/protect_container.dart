part of protect;

class _PROTECTContainer {
  var FullPaths = <String?>[];
  var _kFileIndex = <_PROTECTEntry>[];
  var _sectors = <_PROTECTBlob>[];
  var _raw = <dynamic, dynamic>{};

  Map<dynamic, dynamic> get raw => _raw;

  set raw(Map<dynamic, dynamic> _) => _raw = Map<dynamic, dynamic>.from(_);

  List<_PROTECTBlob> get sectors => _sectors;

  set sectors(List<_PROTECTBlob> _) => _sectors = List<_PROTECTBlob>.from(_);

  List<_PROTECTEntry> get FileIndex => _kFileIndex;

  set FileIndex(List<_PROTECTEntry> _) {
    _kFileIndex = <_PROTECTEntry>[];
    for (var element in _) {
      _kFileIndex.add(element);
    }
  }
}
