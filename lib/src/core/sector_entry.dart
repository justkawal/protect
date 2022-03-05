part of protect;

class _SectorEntry {
  List<int> _data = <int>[];
  List<int> _nodes = <int>[];
  late String name;

  List<int> get data => _data;

  set data(List<int> _) => _data = List<int>.from(_);

  List<int> get nodes => _nodes;

  set nodes(List<int> _) => _nodes = List<int>.from(_);
}
