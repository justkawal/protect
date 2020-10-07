part of protect;

class _PROTECTEntry {
  /// Variables
  String _name, _storage, _clsid, _ctype;
  _PROTECTBlob _content;
  DateTime _ct, _mt;
  int _color, _type, _state, _start, _size, _l, _r, _c;

  _PROTECTBlob get content => this._content;

  set content(_PROTECTBlob _) {
    this._content = _PROTECTBlob(List<int>.from(_.packageValue));
  }

  DateTime get ct => this._ct;

  set ct(DateTime _) => this._ct = _;

  DateTime get mt => this._mt;

  set mt(DateTime _) => this._mt = _;

  String get name => this._name;

  set name(String _) => this._name = _;

  String get storage => this._storage;

  set storage(String _) => this._storage = _;

  String get clsid => this._clsid;

  set clsid(String _) => this._clsid = _;

  String get ctype => this._ctype;

  set ctype(String _) => this._ctype = _;

  int get color => this._color;

  set color(int _) => this._color = _;

  int get type => this._type;

  set type(int _) => this._type = _;

  int get state => this._state;

  set state(int _) => this._state = _;

  int get start => this._start;

  set start(int _) => this._start = _;

  int get size => this._size;

  set size(int _) => this._size = _;

  int get L => this._l;

  set L(int _) => this._l = _;

  int get R => this._r;

  set R(int _) => this._r = _;

  int get C => this._c;

  set C(int _) => this._c = _;
}
