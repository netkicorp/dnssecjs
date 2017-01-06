var consts = require('native-dns-packet').consts,
    dnsname = require('./name'),
    utils = require('./utils');

var SECURITY_STATUS = exports.SECURITY_STATUS = {
  UNCHECKED: 0,
  BOGUS: 1,
  INDETERMINATE: 2,
  INSECURE: 3,
  SECURE: 4
};

var SRRSet = function () {
  if (!(this instanceof SRRSet)) return new SRRSet();

  this._rrs = [];
  this.nsigs = 0;
  this.position = 0;
  this.securityStatus = SECURITY_STATUS.UNCHECKED;
};

SRRSet.prototype.first = function () {
  if (!this._rrs.length) {
    throw new RangeError("SRRSet Empty");
  }
  return this._rrs[0];
};

SRRSet.prototype.sameRRset = function (record1, record2) {
  var r1type = utils.getRRSetType(record1);
  var r2type = utils.getRRSetType(record2);

  return !!(r1type === r2type && record1.class === record2.class && record1.name === record2.name);
};

SRRSet.prototype.safeAddRR = function (record) {
  if (record.type != consts.NAME_TO_QTYPE.RRSIG) {
    if (this.nsigs === 0) {
      this._rrs.push(record);
    } else {
      this._rrs.splice(this._rrs.length - this.nsigs, 0, record);
    }
  } else {
    this._rrs.push(record);
    this.nsigs++;
  }
};

SRRSet.prototype.addRR = function (record) {
  if (this._rrs.length === 0) {
    return this.safeAddRR(record);
  }

  var first = this.first();
  if (!this.sameRRset(first, record)) {
    throw new TypeError("Record Does Not Match " + consts.QTYPE_TO_NAME[first.type] + " RRSet");
  }

  if (record.ttl != first.ttl) {
    if (record.ttl > first.ttl) {
      record.ttl = first.ttl;
    } else {
      for (var i = 0; i < this._rrs.length; i++) {
        this._rrs[i].ttl = record.ttl;
      }
    }
  }

  if (!utils.arrayContains(record, this._rrs)) {
    this.safeAddRR(record);
  }
};

SRRSet.prototype.deleteRR = function (record) {
  var pos = utils.arrayContains(record, this._rrs);
  if (pos == -1) return;

  if (record.type === consts.NAME_TO_QTYPE.RRSIG) {
    this.nsigs--;
  }
  this._rrs.splice(pos, 1);
};

SRRSet.prototype.clear = function () {
  this._rrs = [];
  this.nsigs = 0;
  this.position = 0;
};

SRRSet.prototype.rrs = function (includeSigs) {
  var sets = [];
  var withSigs = typeof includeSigs === "boolean" ? includeSigs : false;
  for(var i = 0; i < this._rrs.length; i++) {
    if(includeSigs && this._rrs[i].type === consts.NAME_TO_QTYPE.RRSIG) {
      sets.push(this._rrs[i]);
    } else if(this._rrs[i].type !== consts.NAME_TO_QTYPE.RRSIG) {
      sets.push(this._rrs[i]);
    }
  }
  return sets;
};

SRRSet.prototype.sigs = function () {
  var sigs = [];
  for (var i = 0; i < this._rrs.length; i++) {
    if (this._rrs[i].type === consts.NAME_TO_QTYPE.RRSIG) {
      sigs.push(this._rrs[i]);
    }
  }
  return sigs;
};

SRRSet.prototype.size = function () {
  return this._rrs.length - this.nsigs;
};

SRRSet.prototype.getName = function () {
  return dnsname.newNameFromString(this.first().name);
};

SRRSet.prototype.getType = function () {
  return this.first().type;
};

SRRSet.prototype.getDClass = function () {
  return this.first().dclass || this.first().class;
};

SRRSet.prototype.getTtl = function () {
  return this.first().ttl;
};

SRRSet.prototype.getSignerName = function () {
  var sigs = this.sigs();
  if (sigs.length) return dnsname.newNameFromString(sigs[0].signerName);
  return null;
};

SRRSet.prototype.recordsToString = function (isSigs) {
  var records = [];
  for (var i = 0; i < this._rrs.length; i++) {
    if(isSigs && this._rrs[i].type === consts.NAME_TO_QTYPE.RRSIG) {
      records.push(this._rrs[i]);
    } else if (!isSigs && this._rrs[i].type !== consts.NAME_TO_QTYPE.RRSIG) {
      records.push(this._rrs[i]);
    }
  }

  var recout = [];
  for(var j = 0; j < records.length; j++) {
    var rec = "[";
    rec += records[j].name + " ";
    rec += records[j].ttl + " ";
    rec += consts.QCLASS_TO_NAME[records[j].class] + " ";
    rec += consts.QTYPE_TO_NAME[records[j].type] + " ";
    rec += "]";
    recout.push(rec);
  }

  return recout.join(" ");
};

SRRSet.prototype.toString = function () {
  if (this._rrs.length === 0) {
    return "{empty}";
  }

  var out = "{";
  out += this.getName().toString() + " ";
  out += this.getTtl() + " ";
  out += consts.QCLASS_TO_NAME[this.getDClass()] + " ";
  out += consts.QTYPE_TO_NAME[this.getType()] + " ";
  out += this.recordsToString(false);
  if (this.nsigs > 0) {
    out += " sigs: " + this.nsigs;
    out += this.recordsToString(true);
  }
  out += " }";
  return out;

};

exports.SRRSet = SRRSet;