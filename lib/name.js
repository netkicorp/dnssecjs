var utils = require('./utils');

var MAXNAME = 255;
var MAXLABEL = 63;
var MAXLABELS = 128;
var MAXOFFSETS = 7;

var emptyLabel = new Uint8Array(1);
emptyLabel[0] = 0x00;
var wildLabel = new Uint8Array(2);
wildLabel[0] = 0x01;
wildLabel[1] = 0x2A; // '1*';

var copy = function (src, dst) {
  if (src.offset(0) === 0) {
    dst.name = src.name;
    dst.offsets = src.offsets;
  } else {
    var offset0 = src.offset(0);
    var namelen = src.name.length - offset0;
    var labels = src.labels();
    dst.name = new Uint8Array(namelen);
    utils.copyByteArray(src.name, offset0, dst.name, 0, namelen);
    for (var i = 0; i < labels && i < MAXOFFSETS; i++)
      dst.setoffset(i, src.offset(i) - offset0);
    dst.setLabels(labels);
  }
};

var Name = exports.Name = function (rawName) {
  this.offsets = new Uint8Array(8);
  if (typeof rawName === "object") {
    this.name = rawName;
  } else if (typeof rawName === "string") {
    var newName = newNameFromString(rawName);
    this.name = newName.name;
    this.offsets = newName.offsets;
  } else {
    this.name = null;
  }
};

Name.prototype.relativize = function (origin) {
  if (origin == null || !this.subdomain(origin)) return this;

  var newName = new Name(this.name);
  var length = this.length() - origin.length();
  var labels = newName.labels - origin.labels;
  newName.setLabels(labels);
  newName.name = new Uint8Array(length);
  utils.copyByteArray(this.name, this.offset(0), newName.name, 0, length);
  return newName;
};

Name.prototype.wild = function (n) {
  if (n < 1) throw "must replace 1 or more labels";
  var newName = new Name();
  copy(wild, newName);
  newName.append(this.name, this.offset(n), this.getLabels() - n);
  return newName;
};

Name.prototype.isWild = function () {
  if (this.getLabels() === 0) return false;
  return (this.name[0] == 0x01 && this.name[1] == 0x2A);
};

Name.prototype.isAbsolute = function () {
  var nlabels = this.getLabels();
  if (nlabels === 0) return false;
  return this.name[this.offset(nlabels - 1)] === 0;
};

Name.prototype.subdomain = function (domain) {
  var labels = this.getLabels();
  var dlabels = domain.getLabels();
  if (dlabels > labels) return false;
  if (dlabels === labels) return this.equals(domain);
  return domain.equals(this.name, this.offset(labels - dlabels));
};

Name.prototype.equals = function (b, bpos) {

  var tempName, tempOffset;

  if (typeof bpos === "undefined" && typeof b === "object") {
    var arg = b;
    if (arg === this) return true;
    if (arg === null || typeof arg.name === "undefined") return false;
    if (arg.labels() != this.labels()) return false;

    tempName = arg.name;
    tempOffset = arg.offset(0);
    b = tempName;
    bpos = tempOffset;
  }


  var labels = this.getLabels();
  var pos = this.offset(0);
  for (var i = 0; i < labels; i++) {
    if (this.name[pos] !== b[bpos]) return false;
    var len = this.name[pos++];
    bpos++;
    if (len > MAXLABEL)
      throw "invalid label";
    for (var j = 0; j < len; j++) {
      var lc = (this.name[pos] & 0xFF) < 97 ? (this.name[pos] & 0xFF) + 32 : (this.name[pos] & 0xFF);
      var bc = (b[bpos] & 0xFF) < 97 ? (b[bpos] & 0xFF) + 32 : (b[bpos] & 0xFF);
      if (lc !== bc) return false;
      pos++;
      bpos++;
    }
  }
  return true;
};

Name.prototype.compareTo = function (arg) {
  if (this === arg)
    return 0;

  var labels = this.labels();
  var alabels = arg.labels();
  var compares = labels > alabels ? alabels : labels;

  for (var i = 1; i <= compares; i++) {
    var start = this.offset(labels - i);
    var astart = arg.offset(alabels - i);
    var length = this.name[start];
    var alength = arg.name[astart];
    for (var j = 0; j < length && j < alength; j++) {
      var ch = this.name[j + start + 1] & 0xFF;
      ch = ch < 97 ? ch + 32 : ch;

      var ach = arg.name[j + astart + 1] & 0xFF;
      ach = ach < 97 ? ch + 32 : ch;

      var n = ch - ach;
      if (n !== 0)
        return n;
    }
    if (length !== alength)
      return (length - alength);
  }

  return (labels - alabels);
};

Name.prototype.getName = function () {
  return this.name;
};

Name.prototype.setoffset = function (n, offset) {
  if (n > MAXOFFSETS)
    return;
  //var shift = 8 * (7 - n);
  this.offsets[7 - n] = offset;
  //this.offsets &= (~(0xFF << shift));
  //this.offsets |= (offset << shift);
};

Name.prototype.offset = function (n) {
  if (n === 0 && this.getLabels() === 0)
    return 0;
  if (n < 0 || n >= this.getLabels())
    throw "label out of range";
  if (n < MAXOFFSETS) {
    //var shift = 8 * (7 - n);
    //return (this.offsets >>> shift) & 0xFF;
    return this.offsets[7 - n];
  } else {
    var pos = this.offset(MAXOFFSETS - 1);
    for (var i = MAXOFFSETS - 1; i < n; i++)
      pos += this.name[pos] + 1;
    return pos;
  }
};

Name.prototype.getLabels = function () {
  return (this.offsets[0] & 0xFF);
};

Name.prototype.labels = function () {
  return this.getLabels();
};

Name.prototype.setLabels = function (labels) {
  this.offsets[0] = labels;
};

Name.prototype.getLabelString = function (n) {
  var pos = this.offset(n);
  return this.byteString(this.name, pos);
};

Name.prototype.append = function (array, start, n) {
  var length = (this.name == null ? 0 : (this.name.length - this.offset(0)));
  var alength = 0;
  var pos = start;
  for (var i = 0; i < n; i++) {
    var len = array[pos];
    if (len > MAXLABEL)
      throw "invalid label";
    len++;
    pos += len;
    alength += len;
  }

  var newlength = length + alength;
  if (newlength > MAXNAME)
    throw "Name Too Long";
  var labels = this.getLabels();
  var newlabels = labels + n;
  if (newlabels > MAXLABELS)
    throw "Too Many Labels";
  var newname = new Uint8Array(newlength);
  if (length !== 0)
    utils.copyByteArray(this.name, this.offset(0), newname, 0, length);

  utils.copyByteArray(array, start, newname, length, alength);
  this.name = newname;
  pos = length;
  for (var j = 0; j < n; j++) {
    this.setoffset(labels + j, pos);
    pos += (newname[pos] + 1);
  }
  this.setLabels(newlabels);
};

Name.prototype.appendFromString = function (fullName, array, start, n) {
  try {
    this.append(array, start, n);
  } catch (err) {
    throw "Name too long: " + fullName;
  }
};

Name.prototype.appendSafe = function (array, start, n) {
  try {
    this.append(array, start, n);
  } catch (err) {
    // Do Nothing
  }
};

Name.prototype.byteString = function (array, pos) {
  var sb = "";
  var len = array[pos++];
  for (var i = pos; i < pos + len; i++) {
    var b = array[i] & 0xFF;
    if (b <= 0x20 || b >= 0x7F) {
      sb += "\\";
      sb += b;
    } else if (['"', '(', ')', '.', ';', '\\', '@', '$'].indexOf(b) !== -1) {
      sb += "\\";
      sb += String.fromCharCode(b);
    } else {
      sb += String.fromCharCode(b);
    }
  }
  return sb;
};

Name.prototype.toString = function (omitFinalDot) {

  var ofd = omitFinalDot || false;

  var labels = this.getLabels();
  if (labels === 0) return "@";
  else if (labels === 1 && this.name[this.offset(0)] === 0) return ".";

  var sb = "";
  var pos = this.offset(0);
  for (var i = 0; i < labels; i++) {
    var len = this.name[pos];
    if (len > MAXLABEL) return "invalid label";
    if (len === 0) {
      if (!ofd) sb += ".";
      break;
    }
    if (i > 0)
      sb += ".";

    sb += this.byteString(this.name, pos);
    pos += (1 + len);
  }

  return sb;
};

var newNameFromOrigin = exports.newNameFromOrigin = function (s, origin) {
  if (s === "")
    throw "empty name";
  else if (s == "@") {
    if (origin == null)
      copy(empty, this);
    else
      copy(origin, this);
    return;
  } else if (s == ".") {
    copy(root, this);
    return;
  }

  var labelstart = -1;
  var pos = 1;
  var label = new Uint8Array(MAXLABEL + 1);
  var escaped = false;
  var digits = 0;
  var intval = 0;
  var absolute = false;

  var returnName = new Name();

  for (var i = 0; i < s.length; i++) {
    var b = s.charAt(i).charCodeAt(0);
    if (escaped) {
      if (b >= '0'.charCodeAt(0) && b <= '9'.charCodeAt(0) && digits < 3) {
        digits++;
        intval *= 10;
        intval += (b - '0');
        if (intval > 255)
          throw "bad escape";
        if (digits < 3)
          continue;
        b = intval;
      } else if (digits > 0 && digits < 3) {
        throw "bad escape";
      }

      if (pos > MAXLABEL)
        throw "parse exception";

      labelstart = pos;
      label[pos++] = b;
      escaped = false;
    } else if (b == "\\".charCodeAt(0)) {
      escaped = true;
      digits = 0;
      intval = 0;
    } else if (b == '.'.charCodeAt(0)) {
      if (labelstart === -1)
        labelstart = i;

      label[0] = pos - 1;
      returnName.appendFromString(s, label, 0, 1);
      labelstart = -1;
      pos = 1;
    } else {
      if (labelstart === -1)
        labelstart = i;
      if (pos > MAXLABEL)
        throw "label too long";
      label[pos++] = b;
    }
  }
  if (digits > 0 && digits < 3)
    throw "bad escape: " + s;
  if (escaped)
    throw "bad escape: " + s;

  if (labelstart == -1) {
    returnName.appendFromString(s, emptyLabel, 0, 1);
    absolute = true;
  } else {
    label[0] = pos - 1;
    returnName.appendFromString(s, label, 0, 1);
  }
  if (origin != null && !absolute)
    returnName.appendFromString(s, origin.name, origin.offset(0), origin.getLabels());

  return returnName;
};

var newNameFromBytes = exports.newNameFromBytes = function (s) {
  return newNameFromOrigin(s, null);
};

var newNameFromString = exports.newNameFromString = function (s, origin) {

  if (s == ".")
    return root;

  if (typeof origin === "undefined")
    return newNameFromOrigin(s, null);

  if (s == "@" && origin !== null) {
    return origin;
  } else if (s == ".") {
    return root;
  }

  return newNameFromOrigin(s, origin);
};

var newNameRemoveLabels = exports.newNameRemoveLabels = function (src, n) {

  if (typeof src === "string") {
    src = newNameFromString(src);
  }

  var slabels = src.getLabels();
  if (n > slabels)
    throw "Attempted to remove too many labels";

  var newname = new Name();
  newname.name = src.name;
  newname.setLabels(slabels - n);
  for (var i = 0; i < MAXOFFSETS && i < (slabels - n); i++) {
    newname.setoffset(i, src.offset(i + n));
  }
  return newname;
};

var empty = exports.empty = {};
var root = exports.root = new Name(emptyLabel);
root.setLabels(1);
var wild = exports.wild = new Name(wildLabel);
wild.setLabels(1);