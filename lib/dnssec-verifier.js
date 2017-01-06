var SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    utils = require('./utils');

var DNSSECVerifier = function () {
  if (!(this instanceof DNSSECVerifier)) return new DNSSECVerifier();

};

DNSSECVerifier.prototype.findKey = function (dnskeyRRset, rrsig) {
  if(rrsig.signerName !== dnskeyRRset.getName().toString()) {
    console.log("findKey: could not find appropriate key because incorrect keyset was supplied. Wanted: " + rrsig.signerName + ", got: " + dnskeyRRset.getName());
    return null;
  }

  var keyid = rrsig.keytag;
  var alg = rrsig.algorithm;
  var res = [];
  var dnskeyrrs = dnskeyRRset.rrs();
  for(var i = 0; i < dnskeyrrs.length; i++) {
    if(dnskeyrrs[i].algorithm == alg && utils.getDnskeyFootprint(dnskeyrrs[i]) == keyid) {
      res.push(dnskeyrrs[i]);
    }
  }

  if(res.length === 0) {
    console.log("findKey: could not find a key matching the algorithm and footprint in supplied keyset.");
    return null;
  }

  return res;
};

DNSSECVerifier.prototype.verifySignature = function (rrset, rrsig, keyrrset) {
  var keys = this.findKey(keyrrset, rrsig);
  if(keys == null) {
    console.log("could not find appropriate key");
    return SECURITY_STATUS.BOGUS;
  }

  var status = SECURITY_STATUS.UNCHECKED;
  for(var i = 0; i < keys.length; i++) {
    try {
      if(!rrset.getName().subdomain(keyrrset.getName())) {
        console.log("signer name is off-tree");
        status = SECURITY_STATUS.BOGUS;
        continue;
      }

      utils.verifyRRset(rrset, rrsig, keys[i]);
      return SECURITY_STATUS.SECURE;
    } catch (err) {
      console.log("Failed to validate RRset: " + err);
      status = SECURITY_STATUS.BOGUS;
    }
  }
  return status;
};

DNSSECVerifier.prototype.verifyRRSet = function (rrset, keyrrset) {
  var sigs = rrset.sigs();
  if(sigs.length === 0) {
    console.log("RRset failed to verify due to lack of signatures");
    return SECURITY_STATUS.BOGUS;
  }

  for(var i = 0; i < sigs.length; i++) {
    var secStatus = this.verifySignature(rrset, sigs[i], keyrrset);
    if(secStatus == SECURITY_STATUS.SECURE) {
      return secStatus;
    }
  }

  console.log("RRset failed to verify: all signatures were BOGUS");
  return SECURITY_STATUS.BOGUS;
};

DNSSECVerifier.prototype.verifyWithSingleKey = function (rrset, dnskey) {
  var sigs = rrset.sigs();
  if(sigs.length === 0) {
    console.log("RRset failed to verify due to lack of signatures");
    return SECURITY_STATUS.BOGUS;
  }
  for(var i = 0; i < sigs.length; i++) {
    if(sigs[i].keytag != utils.getDnskeyFootprint(dnskey)) {
      continue;
    }

    try {
      utils.verifyRRset(rrset, sigs[i], dnskey);
      return SECURITY_STATUS.SECURE;
    } catch(err) {
      console.log("Failed to validate RRset: " + err);
    }
  }

  console.log("RRset failed to verify: all signatures were BOGUS");
  return SECURITY_STATUS.BOGUS;
};

exports.DNSSECVerifier = DNSSECVerifier;