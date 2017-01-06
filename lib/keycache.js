var consts = require('native-dns-packet').consts,
    dnsname = require('./name'),
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS;

var DEFAULT_MAX_TTL = 900;
var DEFAULT_MAX_CACHE_SIZE = 1000;

var CacheEntry = function(keyEntry, maxttl) {
  if (!(this instanceof CacheEntry)) return new CacheEntry();

  var ttl = keyEntry.ttl;
  if(ttl > maxttl) {
    ttl = maxttl;
  }
  this.expiration = new Date();
  this.expiration.setSeconds(this.expiration.getSeconds() + ttl);
  this.keyEntry = keyEntry;
};

var KeyCache = function () {
  if (!(this instanceof KeyCache)) return new KeyCache();

  this.cache = {};
  this.maxttl = DEFAULT_MAX_TTL;
  this.maxCacheSize = DEFAULT_MAX_CACHE_SIZE;
};

KeyCache.prototype.find = function (name, dclass) {
  var nameObj;
  if(typeof name === "string") {
    nameObj = dnsname.newNameFromString(name);
  } else {
    nameObj = name;
  }
  while(nameObj.labels() > 0) {
    var k = this.key(nameObj.toString(), dclass);
    var entry = this.lookupEntry(k);
    if(entry != null) {
      return entry;
    }

    nameObj = dnsname.newNameRemoveLabels(nameObj, 1);
  }
  return null;
};

KeyCache.prototype.store = function (ke) {
  if(ke.rrset !== null) {
    if(ke.rrset.getType() !== consts.NAME_TO_QTYPE.DNSKEY) {
      return ke;
    }
    if(ke.rrset.securityStatus !== SECURITY_STATUS.SECURE ) {
      return ke;
    }
  }

  var k = this.key(ke.name, ke.dclass);
  this.cache[k] = new CacheEntry(ke, this.maxttl);
  return ke;
};

KeyCache.prototype.key = function (name, dclass) {
  return "K" + dclass + "/" + name;
};

KeyCache.prototype.lookupEntry = function (key) {
  if(!(key in this.cache)) {
    return null;
  }

  if(this.cache[key].expiration <= new Date()) {
    delete this.cache[key];
    return null;
  }

  return this.cache[key].keyEntry;
};

exports.KeyCache = KeyCache;