part of protect;

class _SectorList {
  late String name;
  List<int> _fatAddrs = <int>[];
  final Map<String, _SectorEntry> _map = <String, _SectorEntry>{};
  late int ssz;

  _SectorEntry? operator [](String key) {
    return _map[key];
  }

  operator []=(String key, _SectorEntry entry) {
    _map[key] = entry;
  }

  List<int> get fatAddrs {
    return _fatAddrs;
  }

  set fatAddrs(List<int> fatAddress) {
    _fatAddrs = List<int>.from(fatAddress);
  }
}
