part of protect;

void prepBlob(_PROTECTBlob blob, int pos) => blob.l = pos;

_PROTECTBlob newBuf(int sz) {
  var o = _PROTECTBlob(List<int>.filled(sz, 0));
  prepBlob(o, 0);
  return o;
}

class _PROTECT {
  int namecmp(String l, String r) {
    List<String> L = l.split('/'), R = r.split('/');
    int c = 0, Z = min(L.length, R.length);
    for (var i = 0; i < Z; ++i) {
      c = L[i].length - R[i].length;
      if (c != 0) return c;
      if (L[i] != R[i]) {
        final Lp = L[i].toInt();
        if (Lp == null) {
          return -1;
        }
        final Rp = R[i].toInt();
        if (Rp == null) {
          return -1;
        }
        return L[i].toInt()! < R[i].toInt()! ? -1 : 1;
      }
    }
    return L.length - R.length;
  }

  String dirname(String p) {
    if (p.length - 1 >= 0 && p[p.length - 1] == '/') {
      return (!p.slice(0, -1).contains('/')) ? p : dirname(p.slice(0, -1));
    }
    var c = p.lastIndexOf('/');
    return (c == -1) ? p : p.slice(0, c + 1);
  }

  String filename(String p) {
    if (p[p.length - 1] == '/') return filename(p.slice(0, -1));
    int c = p.lastIndexOf('/');
    return (c == -1) ? p : p.slice(c + 1);
  }

  _PROTECTContainer parse(List<int> file /* , [String root] */) {
    if (file.length < 512) {
      throw ArgumentError(
          '_PROTECT file size ' + file.length.toString() + ' < 512');
    }
    int mver = 3;
    int ssz = 512;
    int nmfs = 0; // number of mini FAT sectors
    int difatSecCnt = 0;
    int dirStart = 0;
    int minifatStart = 0;
    int difatStart = 0;

    List<int> fatAddrs = <int>[];

    /* [MS-_PROTECT] 2.2 Compound File Header */
    _PROTECTBlob blob = _PROTECTBlob(file.slice(0, 512));
    prepBlob(blob, 0);

    /* major version */
    var mv = checkGetMver(blob);
    mver = mv[0];
    switch (mver) {
      case 3:
        ssz = 512;
        break;
      case 4:
        ssz = 4096;
        break;
      default:
        throw ArgumentError(
            'Major Version: Expected 3 or 4 saw ' + mver.toString());
    }

    /* reprocess header */
    if (ssz != 512) {
      blob = _PROTECTBlob(file.slice(0, ssz));
      prepBlob(blob, 28);
    }
    /* Save header for final object */
    List<int> header = file.slice(0, ssz);

    checkShifts(blob, mver);

    // Number of Directory Sectors
    int dirCnt = blob.readShift(4, 'i');
    if (mver == 3 && dirCnt != 0) {
      throw ArgumentError(
          '# Directory Sectors: Expected 0 saw ' + dirCnt.toString());
    }

    // Number of FAT Sectors
    blob.l += 4;

    // First Directory Sector Location
    dirStart = blob.readShift(4, 'i');

    // Transaction Signature
    blob.l += 4;

    // Mini Stream Cutoff Size
    blob.chk('00100000', 'Mini Stream Cutoff Size: ');

    // First Mini FAT Sector Location
    minifatStart = blob.readShift(4, 'i');

    // Number of Mini FAT Sectors
    nmfs = blob.readShift(4, 'i');

    // First DIFAT sector location
    difatStart = blob.readShift(4, 'i');

    // Number of DIFAT Sectors
    difatSecCnt = blob.readShift(4, 'i');

    // Grab FAT Sector Locations
    for (int q = -1, j = 0; j < 109; ++j) {
      q = blob.readShift(4, 'i');
      if (q < 0) break;
      if (fatAddrs.isEmpty || fatAddrs.length >= j) {
        fatAddrs.add(q);
      } else {
        fatAddrs[j] = q;
      }
    }

    /** Break the file up into sectors */
    List<List<int>> sectors = sectorify(file, ssz);

    sleuthFat(difatStart, difatSecCnt, sectors, ssz, fatAddrs);

    /** Chains */
    _SectorList sectorList = makeSectorList(sectors, dirStart, fatAddrs, ssz);

    sectorList[dirStart.toString()]!.name = '!Directory';
    if (nmfs > 0 && minifatStart != _ENDOFCHAIN) {
      sectorList[minifatStart.toString()]!.name = '!MiniFAT';
    }
    sectorList[fatAddrs[0].toString()]!.name = '!FAT';
    sectorList.fatAddrs = fatAddrs;
    sectorList.ssz = ssz;

    /* [MS-_PROTECT] 2.6.1 Compound File Directory Entry */
    Map<String, _PROTECTEntry> files = <String, _PROTECTEntry>{};
    List<String> Paths = <String>[], FullPaths = <String>[];
    List<_PROTECTEntry> FileIndex = <_PROTECTEntry>[];

    readDirectory(dirStart, sectorList, sectors, Paths, nmfs, files, FileIndex,
        minifatStart);

    buildFullPaths(FileIndex, FullPaths, Paths);
    if (Paths.isNotEmpty) {
      Paths.removeAt(0);
    }

    var o = _PROTECTContainer();
    o.FileIndex = FileIndex;
    o.FullPaths = FullPaths;
    // raw enabled
    o.raw = {'header': header, 'sectors': sectors};
    return o;
  }

  List<int> checkGetMver(_PROTECTBlob blob) {
    if (blob[blob.l] == 0x50 && blob[blob.l + 1] == 0x4b) return [0, 0];
    // header signature 8
    blob.chk(_HEADER_SIGNATURE, 'Header Signature: ');

    // clsid 16
    //blob.chk(_HEADER_CLSID, 'CLSID: ');
    blob.l += 16;

    // minor version 2
    int mver = blob.readShift(2, 'u');

    return [blob.readShift(2, 'u'), mver];
  }

  void checkShifts(_PROTECTBlob blob, int mver) {
    var shift = 0x09;

    blob.l += 2;

    // Sector Shift
    switch ((shift = blob.readShift(2))) {
      case 0x09:
        if (mver != 3) {
          throw ArgumentError(
              'Sector Shift: Expected 9 saw ' + shift.toString());
        }
        break;
      case 0x0c:
        if (mver != 4) {
          throw ArgumentError(
              'Sector Shift: Expected 12 saw ' + shift.toString());
        }
        break;
      default:
        throw ArgumentError(
            'Sector Shift: Expected 9 or 12 saw ' + shift.toString());
    }

    // Mini Sector Shift
    blob.chk('0600', 'Mini Sector Shift: ');

    // Reserved
    blob.chk('000000000000', 'Reserved: ');
  }

  List<List<int>> sectorify(List<int> file, int ssz) {
    int nsectors = (file.length / ssz).ceil() - 1;
    List<List<int>> sectors = <List<int>>[];
    for (int i = 1; i < nsectors; ++i) {
      sectors.add(file.slice(i * ssz, (i + 1) * ssz));
    }
    sectors.add(file.slice(nsectors * ssz));
    return sectors;
  }

  void buildFullPaths(
      List<_PROTECTEntry> FI, List<String> FP, List<String> Paths) {
    int i = 0, L = 0, R = 0, C = 0, j = 0, pl = Paths.length;
    List<int> dad = <int>[], q = <int>[];

    for (; i < pl; ++i) {
      dad.add(i);
      q.add(i);
      FP.add(Paths[i]);
    }

    for (; j < q.length; ++j) {
      i = q[j];
      L = FI[i].L!;
      R = FI[i].R!;
      C = FI[i].C!;
      if (dad[i] == i) {
        if (L != -1 && dad[L] != L) dad[i] = dad[L];
        if (R != -1 && dad[R] != R) dad[i] = dad[R];
      }
      if (C != -1) dad[C] = i;
      if (L != -1 && i != dad[i]) {
        dad[L] = dad[i];
        if (q.lastIndexOf(L) < j) q.add(L);
      }
      if (R != -1 && i != dad[i]) {
        dad[R] = dad[i];
        if (q.lastIndexOf(R) < j) q.add(R);
      }
    }
    for (i = 1; i < pl; ++i) {
      if (dad[i] == i) {
        if (R != -1 && dad[R] != R) {
          dad[i] = dad[R];
        } else if (L != -1 && dad[L] != L) {
          dad[i] = dad[L];
        }
      }
    }

    for (i = 1; i < pl; ++i) {
      if (FI[i].type == 0) continue;
      j = i;
      if (j != dad[j]) {
        do {
          j = dad[j];
          FP[i] = FP[j] + '/' + FP[i];
        } while (j != 0 && -1 != dad[j] && j != dad[j]);
      }
      dad[i] = -1;
    }

    FP[0] += '/';
    for (i = 1; i < pl; ++i) {
      if (FI[i].type != 2) FP[i] += '/';
    }
  }

  _PROTECTBlob getMfatEntry(
      _PROTECTEntry entry, List<int> payload, List<int>? mini) {
    int start = entry.start!, size = entry.size!;
    var o = <List<int>>[];
    int idx = start;
    while (mini != null && mini.isNotEmpty && size > 0 && idx >= 0) {
      o.add(payload.slice(idx * _MSSZ, idx * _MSSZ + _MSSZ));
      size -= _MSSZ;
      idx = readInt32LE(mini, idx * 4);
    }
    if (o.isEmpty) return newBuf(0);
    return _PROTECTBlob(toBuffer(o).slice(0, entry.size));
  }

  void sleuthFat(
      int idx, int cnt, List<List<int>> sectors, int ssz, List<int> fatAddrs) {
    var q = _ENDOFCHAIN;
    if (idx == _ENDOFCHAIN) {
      if (cnt != 0) throw ArgumentError('DIFAT chain shorter than expected');
    } else if (idx != -1 && idx < sectors.length) {
      var sector = idx < sectors.length ? sectors[idx] : null;
      int m = zeroFillRightShift(ssz, 2) - 1;
      if (sector == null) return;
      for (int i = 0; i < m; ++i) {
        if ((q = readInt32LE(sector, i * 4)) == _ENDOFCHAIN) break;
        fatAddrs.add(q);
      }
      sleuthFat(readInt32LE(sector, ssz - 4), cnt - 1, sectors, ssz, fatAddrs);
    }
  }

  _SectorEntry getSectorList(List<List<int>> sectors, int start,
      List<int> fatAddrs, int ssz, List<bool>? chkd) {
    List<int> buf = <int>[];

    List<List<int>> bufChain = <List<int>>[];
    if (chkd == null || chkd.isEmpty) chkd = <bool>[];
    int modulus = ssz - 1, j = 0, jj = 0;
    for (j = start; j >= 0;) {
      chkd[j] = true;
      buf[buf.length] = j;
      bufChain.add(sectors[j]);
      int addr = fatAddrs[(j * 4 / ssz).floor()];
      jj = ((j * 4) & modulus);
      if (ssz < 4 + jj) {
        throw ArgumentError(
            'FAT boundary crossed: ' + j.toString() + ' 4 ' + ssz.toString());
      }
      if (/* sectors == null || */ sectors.isEmpty || addr >= sectors.length) {
        break;
      }
      j = readInt32LE(sectors[addr], jj);
    }
    var sec = _SectorEntry();
    sec.nodes = buf;
    sec.data = toBuffer(bufChain);
    return sec;
  }

  _SectorList makeSectorList(
      List<List<int>> sectors, int dirStart, List<int> fatAddrs, int ssz) {
    int sl = sectors.length;

    var sectorList = _SectorList();

    Map<int, bool> chkd = <int, bool>{};
    List<int> buf = <int>[];
    List<List<int>> bufChain = <List<int>>[];

    int modulus = ssz - 1, i = 0, j = 0, k = 0, jj = 0;
    for (i = 0; i < sl; ++i) {
      buf = <int>[];
      k = (i + dirStart);
      if (k >= sl) k -= sl;
      if (k < chkd.length && chkd[k] != null && chkd[k]!) continue;
      bufChain = [];
      Map<int, bool> seen = <int, bool>{};
      for (j = k; j >= 0;) {
        seen[j] = true;
        chkd[j] = true;
        buf.add(j);
        bufChain.add(sectors[j]);
        int addr = fatAddrs[(j * 4 / ssz).floor()];
        jj = ((j * 4) & modulus);
        if (ssz < 4 + jj) {
          throw ArgumentError(
              'FAT boundary crossed: ' + j.toString() + ' 4 ' + ssz.toString());
        }
        //if (sectors[addr] == null) break;
        j = readInt32LE(sectors[addr], jj);
        if (seen[j] != null && seen[j]!) break;
      }
      var sec = _SectorEntry();
      sec.nodes = buf;
      sec.data = toBuffer(bufChain);
      sectorList[k.toString()] = sec;
    }
    return sectorList;
  }

  void readDirectory(
      int dirStart,
      _SectorList sectorList,
      List<List<int>> sectors,
      List<String> Paths,
      int nmfs,
      Map<String, _PROTECTEntry> files,
      List<_PROTECTEntry> FileIndex,
      int mini) {
    int minifatStore = 0, pl = (Paths.isNotEmpty ? 2 : 0), i = 0, namelen = 0;
    List<int> sector = sectorList['$dirStart']!.data;
    String name;
    for (; i < sector.length; i += 128) {
      _PROTECTBlob blob = _PROTECTBlob(sector.slice(i, i + 128));
      prepBlob(blob, 64);
      namelen = blob.readShift(2);
      name = utf16le(blob, 0, namelen - pl);
      Paths.add(name);
      var o = _PROTECTEntry();

      o.name = name;
      o.type = blob.readShift(1);
      o.color = blob.readShift(1);
      o.L = blob.readShift(4, 'i');
      o.R = blob.readShift(4, 'i');
      o.C = blob.readShift(4, 'i');
      o.clsid = blob.readShift(16).toString();
      o.state = blob.readShift(4, 'i');
      o.start = 0;
      o.size = 0;

      int ctime = blob.readShift(2) +
          blob.readShift(2) +
          blob.readShift(2) +
          blob.readShift(2);
      if (ctime != 0) o.ct = readDate(blob, blob.l - 8);
      int mtime = blob.readShift(2) +
          blob.readShift(2) +
          blob.readShift(2) +
          blob.readShift(2);
      if (mtime != 0) o.mt = readDate(blob, blob.l - 8);
      o.start = blob.readShift(4, 'i');
      o.size = blob.readShift(4, 'i');
      if (o.size! < 0 && o.start! < 0) {
        o.size = o.type = 0;
        o.start = _ENDOFCHAIN;
        o.name = '';
      }
      if (o.type == 5) {
        /* root */
        minifatStore = o.start!;
        if (nmfs > 0 && minifatStore != _ENDOFCHAIN) {
          sectorList[minifatStore.toString()]!.name = '!StreamData';
        }
        /*minifat_size = o.size;*/
      } else if (o.size! >= 4096) {
        o.storage = 'fat';
        if (sectorList['${o.start}'] == null) {
          sectorList[o.start.toString()] = getSectorList(
              sectors, o.start!, sectorList.fatAddrs, sectorList.ssz, null);
        }
        sectorList['${o.start}']!.name = o.name!;
        o.content =
            _PROTECTBlob(sectorList['${o.start}']!.data.slice(0, o.size));
      } else {
        o.storage = 'minifat';
        if (o.size! < 0) {
          o.size = 0;
        } else if (minifatStore != _ENDOFCHAIN &&
            o.start != _ENDOFCHAIN &&
            sectorList['$minifatStore'] != null) {
          o.content = getMfatEntry(
              o, sectorList['$minifatStore']!.data, sectorList['$mini']?.data);
        }
      }
      if (o.content != null) prepBlob(o.content!, 0);
      files[name] = o;
      FileIndex.add(o);
    }
  }

  DateTime readDate(blob, offset) {
    return DateTime(
        0, // year
        0, // month
        0, // day
        0, // hour
        0, // minute
        0, // second
        (((readUInt32LE(blob, offset + 4) / 1e7) * pow(2, 32) +
                        readUInt32LE(blob, offset) / 1e7) -
                    11644473600)
                .floor() *
            1000);
  }

  void init_protect(_PROTECTContainer protect) {
    String root = 'Root Entry';
    if (/* protect.FullPaths == null || */ protect.FullPaths.isEmpty) {
      protect.FullPaths = <String>[];
    }
    if (/* protect.FileIndex == null || */ protect.FileIndex.isEmpty) {
      protect.FileIndex = <_PROTECTEntry>[];
    }
    if (protect.FullPaths.length != protect.FileIndex.length) {
      throw ArgumentError('inconsistent _PROTECT structure');
    }
    if (protect.FullPaths.isEmpty) {
      protect.FullPaths.add(root + '/');
      var protectEntry = _PROTECTEntry();
      protectEntry.name = root;
      protectEntry.type = 5;
      protect.FileIndex.add(protectEntry);
    }
    seed_protect(protect);
  }

  void seed_protect(_PROTECTContainer protect) {
    var nm = '\u0001PROTEKT';
    if (find(protect, '/' + nm) != null) return;
    var p = newBuf(4);
    p[0] = 55;
    p[1] = p[3] = 50;
    p[2] = 54;
    var entry = _PROTECTEntry();
    entry.name = nm;
    entry.type = 2;
    entry.content = p;
    entry.size = 4;
    entry.L = 69;
    entry.R = 69;
    entry.C = 69;
    protect.FileIndex.add(entry);
    protect.FullPaths.add(protect.FullPaths[0]! + nm);
    rebuild_protect(protect);
  }

  void rebuild_protect(_PROTECTContainer protect, [bool? f]) {
    init_protect(protect);
    var gc = false, s = false;
    int i = 0;
    for (i = protect.FullPaths.length - 1; i >= 0; --i) {
      _PROTECTEntry _file = protect.FileIndex[i];
      switch (_file.type) {
        case 0:
          if (s) {
            gc = true;
          } else {
            protect.FileIndex.pop();
            protect.FullPaths.pop();
          }
          break;
        case 1:
        case 2:
        case 5:
          s = true;
          if ((_file.R == null || _file.L == null || _file.C == null) ||
              (_file.R! * _file.L! * _file.C!).isNaN) {
            gc = true;
          }
          if (_file.R != null &&
              _file.L != null &&
              _file.R! > -1 &&
              _file.L! > -1 &&
              _file.R! == _file.L) {
            gc = true;
          }
          break;
        default:
          gc = true;
          break;
      }
    }
    if (!gc && f != null && !f) return;

    var now = DateTime(1987, 1, 19), j = 0;
    List<List<dynamic>> data = <List<dynamic>>[];
    for (i = 0; i < protect.FullPaths.length; ++i) {
      if (protect.FileIndex[i].type == 0) continue;
      data.add([protect.FullPaths[i], protect.FileIndex[i]]);
    }
    for (i = 0; i < data.length; ++i) {
      String dad = dirname(data[i][0]);
      s = false;
      for (j = 0; j < data.length; ++j) {
        if (data[j][0] == dad) s = true;
      }
      if (!s) {
        var entry = _PROTECTEntry();
        entry.name = filename(dad).replaceAll('/', '');
        entry.type = 1;
        entry.clsid = _HEADER_CLSID;
        entry.ct = now;
        entry.mt = now;
        entry.content = null;
        data.add([dad, entry]);
      }
    }

    data.sort((x, y) => namecmp(x[0], y[0]));
    protect.FullPaths = <String>[];
    protect.FileIndex = <_PROTECTEntry>[];
    for (i = 0; i < data.length; ++i) {
      protect.FullPaths.add(data[i][0]);
      protect.FileIndex.add(data[i][1]);
    }
    for (i = 0; i < data.length; ++i) {
      var elt = protect.FileIndex[i];
      var nm = protect.FullPaths[i];

      elt.name = filename(nm!).replaceAll('/', '');
      elt.L = elt.R = elt.C = -(elt.color = 1);
      elt.size = elt.content != null ? elt.content!.length : 0;
      elt.start = 0;
      elt.clsid = elt.clsid ?? _HEADER_CLSID;
      if (i == 0) {
        elt.C = data.length > 1 ? 1 : -1;
        elt.size = 0;
        elt.type = 5;
      } else if (nm.slice(-1) == '/') {
        for (j = i + 1; j < data.length; ++j) {
          if (dirname(protect.FullPaths[j]!) == nm) break;
        }
        elt.C = j >= data.length ? -1 : j;
        for (j = i + 1; j < data.length; ++j) {
          if (dirname(protect.FullPaths[j]!) == dirname(nm)) break;
        }
        elt.R = j >= data.length ? -1 : j;
        elt.type = 1;
      } else {
        if (dirname((i + 1) < protect.FullPaths.length
                ? (protect.FullPaths[i + 1] ?? '')
                : '') ==
            dirname(nm)) elt.R = i + 1;
        elt.type = 2;
      }
    }
  }

  dynamic _write(_PROTECTContainer protect) {
    rebuild_protect(protect);
    List<int> myCustomFunction(_PROTECTContainer protect) {
      var mini_size = 0, fat_size = 0;
      for (var i = 0; i < protect.FileIndex.length; ++i) {
        var file = protect.FileIndex[i];
        if (file.content == null) {
          continue;
        }
        var flen = file.content!.length;
        if (flen > 0) {
          if (flen < 0x1000) {
            mini_size += (flen + 0x3F) >> 6;
          } else {
            fat_size += (flen + 0x01FF) >> 9;
          }
        }
      }
      var dir_cnt = (protect.FullPaths.length + 3) >> 2;
      var mini_cnt = (mini_size + 7) >> 3;
      var mfat_cnt = (mini_size + 0x7F) >> 7;
      var fat_base = mini_cnt + fat_size + dir_cnt + mfat_cnt;
      var fat_cnt = (fat_base + 0x7F) >> 7;
      var difat_cnt = fat_cnt <= 109 ? 0 : ((fat_cnt - 109) / 0x7F).ceil();
      while (((fat_base + fat_cnt + difat_cnt + 0x7F) >> 7) > fat_cnt) {
        difat_cnt = ++fat_cnt <= 109 ? 0 : ((fat_cnt - 109) / 0x7F).ceil();
      }
      final L = <int>[
        1,
        difat_cnt,
        fat_cnt,
        mfat_cnt,
        dir_cnt,
        fat_size,
        mini_size,
        0
      ];
      protect.FileIndex[0].size = mini_size << 6;
      L[7] = (protect.FileIndex[0].start =
              L[0] + L[1] + L[2] + L[3] + L[4] + L[5]) +
          ((L[6] + 7) >> 3);
      return L;
    }

    var L = myCustomFunction(protect);
    var o = newBuf(L[7] << 9);
    var i = 0, T = 0;

    for (i = 0; i < 8; ++i) {
      o.writeShift(1, _HEADER_SIG[i]);
    }
    for (i = 0; i < 8; ++i) {
      o.writeShift(2, 0);
    }
    o.writeShift(2, 0x003E);
    o.writeShift(2, 0x0003);
    o.writeShift(2, 0xFFFE);
    o.writeShift(2, 0x0009);
    o.writeShift(2, 0x0006);
    for (i = 0; i < 3; ++i) {
      o.writeShift(2, 0);
    }
    o.writeShift(4, 0);
    o.writeShift(4, L[2]);
    o.writeShift(4, L[0] + L[1] + L[2] + L[3] - 1);
    o.writeShift(4, 0);
    o.writeShift(4, 1 << 12);
    o.writeShift(
        4, (L[3] /* ?? null */) != 0 ? L[0] + L[1] + L[2] - 1 : _ENDOFCHAIN);
    o.writeShift(4, L[3]);
    o.writeShift(-4, (L[1] /* ?? null */) != 0 ? L[0] - 1 : _ENDOFCHAIN);
    o.writeShift(4, L[1]);
    for (i = 0; i < 109; ++i) {
      o.writeShift(-4, i < L[2] ? L[1] + i : -1);
    }

    if ((L[1] /* ?? null */) != 0) {
      for (T = 0; T < L[1]; ++T) {
        for (; i < 236 + T * 127; ++i) {
          o.writeShift(-4, i < L[2] ? L[1] + i : -1);
        }
        o.writeShift(-4, T == L[1] - 1 ? _ENDOFCHAIN : T + 1);
      }
    }
    void chainit(int w) {
      for (T += w; i < T - 1; ++i) {
        o.writeShift(-4, i + 1);
      }
      if (w != 0) {
        ++i;
        o.writeShift(-4, _ENDOFCHAIN);
      }
    }

    T = i = 0;
    for (T += L[1]; i < T; ++i) {
      o.writeShift(-4, _DIFSECT);
    }
    for (T += L[2]; i < T; ++i) {
      o.writeShift(-4, _FATSECT);
    }
    chainit(L[3]);
    chainit(L[4]);
    var j = 0, flen = 0;
    var file = protect.FileIndex[0];
    for (; j < protect.FileIndex.length; ++j) {
      file = protect.FileIndex[j];
      if (file.content == null) {
        continue;
      }
      /*:: if(file.content == null) throw new Error('unreachable'); */
      flen = file.content!.length;
      if (flen < 0x1000) {
        continue;
      }
      file.start = T;
      chainit((flen + 0x01FF) >> 9);
    }
    chainit((L[6] + 7) >> 3);
    while ((o.l & 0x1FF) != 0) {
      o.writeShift(-4, _ENDOFCHAIN);
    }
    T = i = 0;
    for (j = 0; j < protect.FileIndex.length; ++j) {
      file = protect.FileIndex[j];
      if (file.content == null) continue;
      /*:: if(file.content == null) throw new Error('unreachable'); */
      final tempFlen = file.content?.length;

      if (tempFlen == null || tempFlen == 0 || tempFlen >= 0x1000) {
        continue;
      }
      flen = tempFlen;
      file.start = T;
      chainit((flen + 0x3F) >> 6);
    }
    while ((o.l & 0x1FF) != 0) {
      o.writeShift(-4, _ENDOFCHAIN);
    }
    for (i = 0; i < (L[4] << 2); ++i) {
      String? nm = i < protect.FullPaths.length ? protect.FullPaths[i] : null;
      if (nm == null || nm.isEmpty) {
        for (j = 0; j < 17; ++j) {
          o.writeShift(4, 0);
        }
        for (j = 0; j < 3; ++j) {
          o.writeShift(4, -1);
        }
        for (j = 0; j < 12; ++j) {
          o.writeShift(4, 0);
        }
        continue;
      }
      file = protect.FileIndex[i];
      if (i == 0) file.start = file.size != 0 ? file.start! - 1 : _ENDOFCHAIN;
      String _nm = file.name!;
      flen = 2 * (_nm.length + 1);
      o.writeShift(64, _nm, 'utf16le');
      o.writeShift(2, flen);
      o.writeShift(1, file.type);
      o.writeShift(1, file.color);
      o.writeShift(-4, file.L);
      o.writeShift(-4, file.R);
      o.writeShift(-4, file.C);
      if (file.clsid == null) {
        for (j = 0; j < 4; ++j) {
          o.writeShift(4, 0);
        }
      } else {
        o.writeShift(16, file.clsid, 'hex');
      }
      o.writeShift(4, file.state ?? 0);
      o.writeShift(4, 0);
      o.writeShift(4, 0);
      o.writeShift(4, 0);
      o.writeShift(4, 0);
      o.writeShift(4, file.start);
      o.writeShift(4, file.size);
      o.writeShift(4, 0);
    }
    for (i = 1; i < protect.FileIndex.length; ++i) {
      file = protect.FileIndex[i];
      /*:: if(!file.content) throw new Error('unreachable'); */
      if (file.size! >= 0x1000) {
        o.l = (file.start! + 1) << 9;
        for (j = 0; j < file.size!; ++j) {
          o.writeShift(1, file.content![j]);
        }
        for (; (j & 0x1FF) != 0; ++j) {
          o.writeShift(1, 0);
        }
      }
    }
    for (i = 1; i < protect.FileIndex.length; ++i) {
      file = protect.FileIndex[i];
      /*:: if(!file.content) throw new Error('unreachable'); */
      if (file.size! > 0 && file.size! < 0x1000) {
        for (j = 0; j < file.size!; ++j) {
          o.writeShift(1, file.content![j]);
        }
        for (; (j & 0x3F) != 0; ++j) {
          o.writeShift(1, 0);
        }
      }
    }
    while (o.l < o.length) {
      o.writeShift(1, 0);
    }
    return o;
  }

  _PROTECTEntry? find(_PROTECTContainer protect, String path) {
    var UCFullPaths = protect.FullPaths.map((x) => x!.toUpperCase()).toList();
    var UCPaths = UCFullPaths.map((x) {
      var y = x.split('/');
      return y[y.length - (x.slice(-1) == '/' ? 2 : 1)];
    }).toList();
    var k = false;
    if (path.codeUnitAt(0) == 47 /* '/' */) {
      k = true;
      path = UCFullPaths[0].slice(0, UCFullPaths[0].length - 1) + path;
    } else {
      k = path.contains('/');
    }
    var UCPath = path.toUpperCase();
    var w = k == true ? UCFullPaths.indexOf(UCPath) : UCPaths.indexOf(UCPath);
    if (w != -1) return protect.FileIndex[w];

    var ch1 = RegExp(_chr1);

    bool m = !ch1.hasMatch(UCPath);
    //  UCPath.match(_chr1);
    UCPath = UCPath.replaceAll(_chr0, '');
    if (m) UCPath = UCPath.replaceAll(_chr1, '!');
    for (w = 0; w < UCFullPaths.length; ++w) {
      if ((m ? UCFullPaths[w].replaceAll(_chr1, '!') : UCFullPaths[w])
              .replaceAll(_chr0, '') ==
          UCPath) return protect.FileIndex[w];
      if ((m ? UCPaths[w].replaceAll(_chr1, '!') : UCPaths[w])
              .replaceAll(_chr0, '') ==
          UCPath) return protect.FileIndex[w];
    }
    return null;
  }

  _PROTECTContainer protect_new() {
    var o = _PROTECTContainer();
    init_protect(o);
    return o;
  }

  _PROTECTEntry protect_add(
      _PROTECTContainer protect, String name, List<int> content) {
    init_protect(protect);

    var file = find(protect, name);
    if (file == null) {
      var fpath = protect.FullPaths[0];
      if (name.slice(0, fpath!.length) == fpath) {
        fpath = name;
      } else {
        if (fpath.slice(-1) != '/') fpath += '/';
        fpath = (fpath + name).replaceAll('//', '/');
      }
      file = _PROTECTEntry();
      file.name = filename(name);
      file.type = 2;
      protect.FileIndex.push(file);
      protect.FullPaths.push(fpath);
      protect_gc(protect);
    }
    /*:: if(!file) throw new Error('unreachable'); */
    file.content = _PROTECTBlob(content);
    file.size = /* content != null && */ content.isNotEmpty
        ? content.length
        : 0;
    return file;
  }

  bool protect_del(_PROTECTContainer protect, String name) {
    init_protect(protect);
    var file = find(protect, name);
    if (file != null) {
      for (int j = 0; j < protect.FileIndex.length; ++j) {
        if (protect.FileIndex[j] == file) {
          protect.FileIndex.splice(j, 1);
          protect.FullPaths.splice(j, 1);
          return true;
        }
      }
    }
    return false;
  }

  void protect_gc(_PROTECTContainer protect) {
    rebuild_protect(protect, true);
  }
}
