var base32 = require('base32.js'),
    BufferCursor = require('buffercursor'),
    consts = require('native-dns-packet').consts,
    conv = require('binstring'),
    dnsname = require('./name'),
    jsrsasign = require('jsrsasign'),
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    utils = require('./utils');

var OPT_OUT = 0x01;

var maxIterations = {
  floorKey: function (keysize) {
    if (keysize < 1024)
      return null;
    else if (keysize < 2048)
      return 1024;
    else if (keysize < 4096)
      return 2048;
    else
      return 4096;
  },
  get: function (keyIters) {
    switch (keyIters) {
      case 1024:
        return 150;
      case 2048:
        return 500;
      case 4096:
        return 2500;
    }
  },
  firstKey: function () {
    return 1024;
  }
};

var CEResponse = function (ce, nsec3) {
  if (!(this instanceof CEResponse)) return new CEResponse(ce, nsec3);

  this.closestEncloser = ce || null;
  this.ceNsec3 = nsec3 || null;
  this.ncNsec3 = null;
  this.status = SECURITY_STATUS.UNCHECKED;
};

/*
 Support Functionality
 */
var supportsHashAlgorithm = function (alg) {
  return alg == consts.DIGEST_TO_NUM.SHA1;
};

var hashName = function (name, hashAlg, iterations, salt) {

  if (typeof name !== "string") {
    name = name.toString();
  }
  name = name.toLowerCase();
  var nameBuff = new BufferCursor(new Buffer(name.length * 2));
  utils.namePack(name, nameBuff, {});
  var nameLen = nameBuff.tell();
  nameBuff.seek(0);
  var nameUpdate = nameBuff.slice(nameLen);

  var digest;
  switch (hashAlg) {
    case consts.DIGEST_TO_NUM.SHA1:
      break;
    default:
      throw "Unknown NSEC3 algorithm identifier: " + hashAlg;
  }

  var hash;
  for (var i = 0; i <= iterations; i++) {
    digest = new jsrsasign.MessageDigest({alg: "sha1", "prov": "cryptojs/jsrsa"});
    if (i === 0) {
      digest.updateHex(conv(nameUpdate.buffer, {in: 'buffer', out: 'hex'}));
    } else {
      digest.updateHex(hash);
    }

    if (salt !== null) {
      digest.updateHex(salt);
    }
    hash = digest.digest();
  }
  return conv(hash, {in: 'hex', out: 'bytes'});
};

var ceWildcard = function (closestEncloser) {
  return dnsname.newNameFromOrigin("*", closestEncloser);
};

/* Find NSEC3 Matches */
var findMatchingNSEC3 = function (name, zonename, nsec3s) {
  var b32;
  for (var i = 0; i < nsec3s.length; i++) {
    var nsec3 = nsec3s[i].first();
    var hash = hashName(name, nsec3.hashAlgorithm, nsec3.iterations, conv(nsec3.salt.buffer, {
      in: 'buffer',
      out: 'hex'
    }));

    var b32encoder = new base32.Encoder({type: 'base32hex', lc: false});
    var complete = dnsname.newNameFromString(b32encoder.write(hash).finalize(), zonename);
    if (complete.toString() === nsec3.name) {
      return nsec3;
    }
  }

  return null;
};

var findClosestEncloser = function (name, zonename, nsec3s) {
  while (name.labels() >= zonename.labels()) {
    var nsec3 = findMatchingNSEC3(name, zonename, nsec3s);
    if (nsec3 !== null)
      return new CEResponse(name, nsec3);
    name = dnsname.newNameRemoveLabels(name, 1);
  }
  return null;
};

var nextClosest = function (qname, closestEncloser) {
  var strip = qname.labels() - closestEncloser.labels() - 1;
  return (strip > 0) ? dnsname.newNameRemoveLabels(qname, strip) : qname;
};

var nsec3Covers = function (nsec3, zonename, hash) {
  if (!dnsname.newNameRemoveLabels(nsec3.name, 1).equals(zonename))
    return false;

  var nsec3Name = nsec3.name;
  if (typeof nsec3Name === "string")
    nsec3Name = dnsname.newNameFromString(nsec3Name);

  var b32decoder = new base32.Decoder({type: 'base32hex', lc: false});
  var owner = b32decoder.write(nsec3Name.getLabelString(0)).finalize();
  var next = nsec3.nextHashedOwnerName;

  if (utils.byteArrayCompare(owner, hash) < 0 && utils.byteArrayCompare(hash, next.buffer) < 0)
    return true;

  if (utils.byteArrayCompare(next.buffer, owner) <= 0 && (utils.byteArrayCompare(hash, owner) > 0 || utils.byteArrayCompare(hash, next.buffer) < 0))
    return true;

  return false;

};

var findCoveringNSEC3 = function (name, zonename, nsec3s) {
  for (var i = 0; i < nsec3s.length; i++) {
    var nsec3 = nsec3s[i].first();
    var hash = hashName(name, nsec3.hashAlgorithm, nsec3.iterations, conv(nsec3.salt.buffer, {
      in: 'buffer',
      out: 'hex'
    }));
    if (nsec3Covers(nsec3, zonename, hash))
      return nsec3;
  }
  return null;
};

var proveClosestEncloser = function (qname, zonename, nsec3s) {

  if (typeof qname === "string")
    qname = dnsname.newNameFromString(qname);

  var candidate = findClosestEncloser(qname, zonename, nsec3s);
  if (candidate === null) {
    console.log("proveClosestEncloser: could not find a candidate for the closest encloser.");
    candidate = new CEResponse(dnsname.empty, null);
    candidate.status = SECURITY_STATUS.BOGUS;
    return candidate;
  }

  if (candidate.closestEncloser.equals(qname)) {
    console.log("proveClosestEncloser: proved that qname existed!");
    candidate.status = SECURITY_STATUS.BOGUS;
    return candidate;
  }

  if (candidate.ceNsec3.hasType(consts.NAME_TO_QTYPE.NS) && !candidate.ceNsec3.hasType(consts.NAME_TO_QTYPE.SOA)) {
    if (candidate.ceNsec3.hasType(consts.NAME_TO_QTYPE.DS)) {
      candidate.status = SECURITY_STATUS.INSECURE;
      return candidate;
    }

    console.log("proveClosestEncloser: closest encloser was a delegation!");
    candidate.status = SECURITY_STATUS.BOGUS;
    return candidate;
  }

  if (candidate.ceNsec3.hasType(consts.NAME_TO_QTYPE.DNAME)) {
    console.log("proveClosestEncloser: closest encloser was a DNAME!");
    candidate.status = SECURITY_STATUS.BOGUS;
    return candidate;
  }

  var nextClose = nextClosest(qname, candidate.closestEncloser);
  candidate.ncNsec3 = findCoveringNSEC3(nextClose, zonename, nsec3s);
  if (candidate.ncNsec3 === null) {
    console.log("Could not find proof that the closest encloser was the closest encloser");
    candidate.status = SECURITY_STATUS.BOGUS;
    return candidate;
  }

  candidate.status = SECURITY_STATUS.SECURE;
  return candidate;
};

var validIterations = exports.validIterations = function (nsec, keyCache) {
  var dnskeyRRset = keyCache.find(nsec.getSignerName(), nsec.getDClass()).getRRset();
  var rrs = dnskeyRRset.rrs();

  for (var i = 0; i < rrs.length; i++) {
    var keysize;

    if (rrs[i].algorithm === consts.DNSSEC_ALGO_NAME_TO_NUM.RSAMD5)
      return false;

    var pubkey = utils.toPublicKey(rrs[i]);
    if (!pubkey)
      return false;

    // TODO: Step through with DSA and EC Public Keys
    switch (pubkey.type) {
      case "RSA":
        keysize = pubkey.key.n.bitLength();
        break;
      case "DSA":
        keysize = pubkey.key.params.p.bitLength();
        break;
      case "EC":
        keysize = pubkey.key.params.curve.field.fieldSize();
        break;
    }

    var keyIters = maxIterations.floorKey(keysize);
    if (keyIters === null) {
      keyIters = maxIterations.firstKey();
    }

    keyIters = maxIterations.get(keyIters);
    if (nsec.first().iterations > keyIters)
      return false;

  }

  return true;
};

var stripUnknownAlgNSEC3s = exports.stripUnknownAlgNSEC3s = function (nsec3s) {
  for (var i = nsec3s.length - 1; i >= 0; i--) {
    if (!supportsHashAlgorithm(nsec3s[i].first().hashAlgorithm)) {
      nsec3s.split(i, 1);
    }
  }
};

var proveNodata = exports.proveNodata = function (nsec3s, qname, qtype, zonename) {
  if (nsec3s == null || nsec3s.length === 0) {
    return SECURITY_STATUS.BOGUS;
  }

  var nsec3 = findMatchingNSEC3(qname, zonename, nsec3s);
  if (nsec3 !== null) {
    if (nsec3.hasType(qtype) !== -1) {
      console.log("proveNodata: Matching NSEC3 proved that type existed!");
      return SECURITY_STATUS.BOGUS;
    }

    if (nsec3.hasType(consts.NAME_TO_QTYPE.CNAME)) {
      console.log("proveNodata: Matching NSEC3 proved that a CNAME existed!");
      return SECURITY_STATUS.BOGUS;
    }

    if (qtype === consts.NAME_TO_QTYPE.DS && nsec3.hasType(consts.NAME_TO_QTYPE.SOA) && qname != ".") {
      console.log("proveNodata: apex NSEC3 abused for no DS proof, bogus");
      return SECURITY_STATUS.BOGUS;
    } else if (qtype !== consts.NAME_TO_QTYPE.DS && nsec3.hasType(consts.NAME_TO_QTYPE.NS) && !nsec3.hasType(consts.NAME_TO_QTYPE.SOA)) {
      if (!nsec3.hasType(consts.NAME_TO_QTYPE.DS)) {
        console.log("proveNodata: matching NSEC3 is insecure delegation");
        return SECURITY_STATUS.INSECURE;
      }

      console.log("proveNodata: matching NSEC3 is a delegation, bogus");
      return SECURITY_STATUS.BOGUS;
    }
    return SECURITY_STATUS.SECURE;
  }

  var ce = proveClosestEncloser(qname, zonename, nsec3s);

  if (ce.status === SECURITY_STATUS.BOGUS) {
    console.log("proveNodata: did not match qname, nor found a proven closest encloser.");
    return SECURITY_STATUS.BOGUS;
  } else if (ce.status === SECURITY_STATUS.INSECURE && qtype !== consts.NAME_TO_QTYPE.DS) {
    console.log("proveNodata: closest nsec3 is insecure delegation.");
    return SECURITY_STATUS.INSECURE;
  }

  var wc = ceWildcard(ce.closestEncloser);
  nsec3 = findMatchingNSEC3(wc, zonename, nsec3s);
  if (nsec3 !== null) {
    if (nsec3.hasType(qtype)) {
      console.log("proveNodata: matching wildcard had qtype!");
      return SECURITY_STATUS.BOGUS;
    } else if (nsec3.hasType(consts.NAME_TO_QTYPE.NAME)) {
      console.log("nsec3 nodata proof: matching wildcard had a CNAME, bogus");
      return SECURITY_STATUS.BOGUS;
    }

    if (qtype === consts.NAME_TO_QTYPE.DS && qname.labels() != 1 && nsec3.hasType(consts.NAME_TO_QTYPE.SOA)) {
      console.log("nsec3 nodata proof: matching wildcard for no DS proof has a SOA, bogus");
      return SECURITY_STATUS.BOGUS;
    } else if (qtype !== consts.NAME_TO_QTYPE.DS && nsec3.hasType(consts.NAME_TO_QTYPE.NS) && !nsec3.hasType(consts.NAME_TO_QTYPE.SOA)) {
      console.log("nsec3 nodata proof: matching wilcard is a delegation, bogus");
      return SECURITY_STATUS.BOGUS;
    }

    if (ce.ncNsec3 !== null && (ce.ncNsec3.flags & OPT_OUT) == OPT_OUT) {
      console.log("nsec3 nodata proof: matching wildcard is in optout range, insecure");
      return SECURITY_STATUS.INSECURE;
    }

    return SECURITY_STATUS.SECURE;
  }

  if (ce.ncNsec3 === null) {
    console.log("nsec3 nodata proof: no next closer nsec3");
    return SECURITY_STATUS.BOGUS;
  }

  if ((ce.ncNsec3.flags & OPT_OUT) === 0) {
    if (qtype !== consts.NAME_TO_QTYPE.DS)
      console.log("proveNodata: covering NSEC3 was not opt-out in an opt-out DS NOERROR/NODATA case.");
    else
      console.log("proveNodata: could not find matching NSEC3, nor matching wildcard, and qtype is not DS -- no more options.");

    return SECURITY_STATUS.BOGUS;
  }

  return SECURITY_STATUS.INSECURE;
};

var proveNameError = exports.proveNameError = function (nsec3s, qname, zonename) {
  if (nsec3s === null || nsec3s.length === 0)
    return SECURITY_STATUS.BOGUS;

  var ce = proveClosestEncloser(qname, zonename, nsec3s);
  if(ce.status !== SECURITY_STATUS.SECURE) {
    console.log("proveNameError: failed to prove a closest encloser.");
    return ce.status;
  }

  var wc = ceWildcard(ce.closestEncloser);
  var nsec3 = findCoveringNSEC3(wc, zonename, nsec3s);
  if(nsec3 === null) {
    console.log("proveNameError: could not prove that the applicable wildcard did not exist.");
    return SECURITY_STATUS.BOGUS;
  }

  if((ce.ncNsec3.flags & OPT_OUT) == OPT_OUT) {
    console.log("nsec3 nameerror proof: nc has optout");
    return SECURITY_STATUS.INSECURE;
  }

  return SECURITY_STATUS.SECURE;
};

var allNSEC3sIgnoreable = exports.allNSEC3sIgnoreable = function (nsec3s, dnskeyRRset) {
  var foundNsecs = {};
  for (var i = 0; i < nsec3s.length; i++) {

    var rrs = nsec3s[i].rrs();
    for (var j = 0; j < rrs.length; j++) {
      var current = rrs[j];
      var key = dnsname.newNameRemoveLabels(current.name, 1);
      var previous = foundNsecs[key] || null;

      if (previous !== null) {
        if (current.hashAlgorithm !== previous.hashAlgorithm)
          return true;

        if (current.iterations !== previous.iterations)
          return true;

        if (current.salt === null ^ previous.salt === null)
          return true;

        if (current.salt !== null && !utils.isBufferEqual(current.salt, previous.salt))
          return true;
      } else {
        foundNsecs[key] = current;
      }
    }
  }

  for (i = 0; i < nsec3s.length; i++) {
    if (validIterations(nsec3s[i], dnskeyRRset))
      return false;
  }
  return true;
};