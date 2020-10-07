part of protect;

class _SectorEntry {
  List<int> _data = <int>[];
  List<int> _nodes = <int>[];
  String _name;

  List<int> get data => this._data;

  set data(List<int> _) => this._data = List<int>.from(_);

  List<int> get nodes => this._nodes;

  set nodes(List<int> _) => this._nodes = List<int>.from(_);

  String get name => this._name;

  set name(String _) => this._name = _;
}
