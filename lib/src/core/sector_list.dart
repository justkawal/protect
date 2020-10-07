part of protect;

class _SectorList {
  String name;
  List<int> _fatAddrs;
  Map<String, _SectorEntry> _map = <String, _SectorEntry>{};
  int ssz;

  _SectorEntry operator [](String _) {
    return this._map[_] ?? null;
  }

  operator []=(String key, _SectorEntry _) {
    this._map[key] = _;
  }

  List<int> get fatAddrs {
    return this._fatAddrs;
  }

  set fatAddrs(List<int> _) {
    this._fatAddrs = List<int>.from(_);
  }
}
