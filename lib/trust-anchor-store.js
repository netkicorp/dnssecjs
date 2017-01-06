var consts = require('native-dns-packet').consts,
    dnsname = require('./name'),
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    SRRSet = require('./srrset').SRRSet,
    utils = require('./utils');

var TrustAnchorStore = exports.TrustAnchorStore = function () {
  this.map = {};
};

TrustAnchorStore.prototype.store = function (rrset) {

  var rrs;

  if(rrset.getType() !== consts.NAME_TO_QTYPE.DS && rrset.getType() !== consts.NAME_TO_QTYPE.DNSKEY) {
    throw "Trust anchors can only be DS or DNSKEY records";
  }

  if(rrset.getType() === consts.NAME_TO_QTYPE.DNSKEY) {
    var temp = new SRRSet();
    rrs = rrset.rrs();
    for(var i = 0; i < rrs.length; i++) {
      var key = rrs[i];
      var r = {
        name: key.name,
        class: key.dclass || key.class,
        ttl: key.ttl,
        keytag: utils.getDnskeyFootprint(key),
        algorithm: key.algorithm,
        digestType: consts.DIGEST_TO_NUM.SHA384,
        digest: utils.generateDSDigest(key, consts.DIGEST_TO_NUM.SHA384)
      };
      temp.addRR(r);
    }
    rrset = temp;
  }

  var k = this.key(rrset.getName(), rrset.getDClass());
  rrset.securityStatus = SECURITY_STATUS.SECURE;
  var previous = this.map[k];
  this.map[k] = rrset;

  if(typeof previous !== "undefined") {
    rrs = previous.rrs();
    for(var j = 0; j < rrs.length; j++) {
      rrset.addRR(rrs[j]);
    }
  }
};

TrustAnchorStore.prototype.find = function (name, dclass) {
  var nameObj = dnsname.newNameFromString(name);
  while(nameObj.labels() > 0) {
    var k = this.key(nameObj.toString(), dclass);
    var r = this.lookup(k);
    if(r !== null) {
      return r;
    }
    nameObj = dnsname.newNameRemoveLabels(nameObj, 1);
  }

  return null;
};

TrustAnchorStore.prototype.clear = function () {
  this.map = {};
};

TrustAnchorStore.prototype.lookup = function (key) {
  if(this.map[key]) return this.map[key];
  return null;
};

TrustAnchorStore.prototype.key = function(n, dclass) {
  return "T" + dclass + "/" + n;
};