var Name = require('./name');

var KeyEntry = function(opts) {
  if (!(this instanceof KeyEntry)) return new KeyEntry();

  this.rrset = opts.rrset || null;
  this.name = opts.name || "";
  this.dclass = opts.dclass || 0;
  this.ttl = opts.ttl || 0;
  this.isBad = opts.isBad || false;
  this.badReason = opts.badReason || null;
};

KeyEntry.prototype.isNull = function () {
  return !this.isBad && this.rrset == null;
};

KeyEntry.prototype.isGood = function() {
  return !this.isBad && this.rrset != null;
};

KeyEntry.prototype.getRRset = function() {
  return this.rrset;
};

KeyEntry.prototype.setBadReason = function(reason) {
  this.badReason = reason;
};

KeyEntry.prototype.getName = function () {
  if(typeof this.name === "string") {
    return Name.newNameFromString(this.name);
  }
  return this.name;
};

var newKeyEntry = exports.newKeyEntry = function (rrset) {
  return new KeyEntry({
    rrset: rrset,
    name: rrset.getName().toString(),
    dclass: rrset.getDClass(),
    ttl: rrset.getTtl()
  });
};

var newNullKeyEntry = exports.newNullKeyEntry = function (name,dclass, ttl) {
  return new KeyEntry({
    name: name,
    dclass: dclass,
    ttl: ttl,
    isBad: false
  });
};

var newBadKeyEntry = exports.newBadKeyEntry = function(name, dclass, ttl) {
  return new KeyEntry({
    name: name,
    dclass: dclass,
    ttl: ttl,
    isBad: true
  });
};

exports.KeyEntry = KeyEntry;