part of protect;

class _PROTECTContainer {
  var FullPaths = <String>[];
  var _kFileIndex = <_PROTECTEntry>[];
  var _sectors = <_PROTECTBlob>[];
  var _raw = <dynamic, dynamic>{};

  Map<dynamic, dynamic> get raw => this._raw;

  set raw(Map<dynamic, dynamic> _) => this._raw = Map<dynamic, dynamic>.from(_);

  List<_PROTECTBlob> get sectors => this._sectors;

  set sectors(List<_PROTECTBlob> _) =>
      this._sectors = List<_PROTECTBlob>.from(_);

  List<_PROTECTEntry> get FileIndex => _kFileIndex;

  set FileIndex(List<_PROTECTEntry> _) {
    _kFileIndex = <_PROTECTEntry>[];
    _.forEach((element) {
      _kFileIndex.add(element);
    });
  }
}
