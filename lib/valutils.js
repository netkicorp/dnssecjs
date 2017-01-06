var consts = require('native-dns-packet').consts,
    conv = require('binstring'),
    DNSSECVerifier = require('./dnssec-verifier').DNSSECVerifier,
    dnsname = require('./name'),
    KeyEntry = require('./keyentry'),
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    utils = require('./utils');

var RESPONSE_CLASSIFICATION = exports.RESPONSE_CLASSIFICATION = {
  UNKNOWN: 0,
  POSITIVE: 1,
  CNAME: 2,
  NODATA: 3,
  NAMEERROR: 4,
  ANY: 5,
  CNAME_NODATA: 6,
  CNAME_NAMEERROR: 7
};

var isDigestSupported = function (digestId) {
  if (typeof digestId === "string")
    digestId = parseInt(digestId);
  switch (digestId) {
    case consts.DIGEST_TO_NUM.SHA1:
    case consts.DIGEST_TO_NUM.SHA256:
    case consts.DIGEST_TO_NUM.SHA384:
      return true;
    default:
      return false;
  }
};

var atLeastOneDigestSupported = function (dsRecords) {
  var records = dsRecords.rrs();
  for (var i = 0; i < records.length; i++) {
    if (records[i].type === consts.NAME_TO_QTYPE.DS) {
      if (isDigestSupported(records[i].digestType)) {
        return true;
      }
    }
  }
  return false;
};

var isAlgorithmSupported = function (algorithmId) {
  if (typeof algorithmId === "string")
    algorithmId = parseInt(algorithmId);
  switch (algorithmId) {
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSAMD5:
      return false; // obsoleted by rfc6944

    case consts.DNSSEC_ALGO_NAME_TO_NUM.DSA:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.DSANSEC3SHA1:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA1:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA1NSEC3SHA1:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA256:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA512:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP256SHA256:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP384SHA384:
      return true;

    default:
      return false;
  }
};

var atLeastOneSupportedAlgorithm = exports.atLeastOneSupportedAlgorithm = function (dsRecords) {
  var records = dsRecords.rrs();
  for (var i = 0; i < records.length; i++) {
    if (records[i].type == consts.NAME_TO_QTYPE.DS) {
      if (isAlgorithmSupported(records[i].algorithm)) {
        return true;
      }
    }
  }
  return false;
};

var hasSignedNsecs = exports.hasSignedNsecs = function (message) {
  var authorityRRsets = message.getSectionRRsets("authority");
  for (var i = 0; i < authorityRRsets.length; i++) {
    if (authorityRRsets[i].getType() == consts.NAME_TO_QTYPE.NSEC || authorityRRsets[i].getType() == consts.NAME_TO_QTYPE.NSEC3) {
      if (authorityRRsets[i].sigs().length) {
        return true;
      }
    }
  }
  return false;
};

var nsecProvesNoDS = exports.nsecProvesNoDS = function (nsec, qname) {
  if ((nsec.hasType(consts.NAME_TO_QTYPE.SOA) && qname != ".") || nsec.hasType(consts.NAME_TO_QTYPE.DS)) {
    return SECURITY_STATUS.BOGUS;
  }
  if (!nsec.hasType(consts.NAME_TO_QTYPE.NS)) {
    return SECURITY_STATUS.INSECURE;
  }
  return SECURITY_STATUS.SECURE;
};

var nsecProvesNodata = exports.NsecProvesNodata = function (nsec, qname, qtype) {
  var result = new utils.NsecProvesNodataResponse();
  if (nsec.name != qname) {
    // TODO: We may need to implement some utilities to handle names for comparison, lexigraphical ordering, etc
    if (utils.strictSubdomain(nsec.next, qname) && nsec.name < qname) {
      result.result = true;
      return result;
    }

    if (nsec.name == "WILD") {
      var ce = nsec.name.split('.').splice(1).join('.');

      if (utils.strictSubdomain(qname, ce)) {
        if (nsec.hasType(consts.NAME_TO_QTYPE.CNAME)) {
          result.result = false;
          return result;
        }
        if (nsec.hasType(consts.NAME_TO_QTYPE.NS) && !nsec.hasType(consts.NAME_TO_QTYPE.SOA)) {
          result.result = false;
          return result;
        }
        if (nsec.hasType(qtype)) {
          result.result = false;
          return result;
        }
      }

      result.wc = ce;
      result.result = true;
      return result;
    }

    result.result = true;
    return result;
  }

  if (nsec.hasType(qtype)) {
    result.result = false;
    return result;
  }

  if (nsec.hasType(consts.NAME_TO_QTYPE.CNAME)) {
    result.result = false;
    return result;
  }

  if (qtype == consts.NAME_TO_QTYPE.DS && nsec.hasType(consts.NAME_TO_QTYPE.NS) && !nsec.hasType(consts.NAME_TO_QTYPE.SOA)) {
    result.result = false;
    return result;
  } else if (qtype == consts.NAME_TO_QTYPE.DS && nsec.hasType(consts.NAME_TO_QTYPE.SOA) && qname != ".") {
    result.result = false;
    return result;
  }

  result.result = true;
  return result;

};

var nsecProvesNodataDsReply = exports.nsecProvesNodataDsReply = function (request, response, keyRRset) {
  var qname = request.getQuestion().name;
  var qclass = consts.NAME_TO_QCLASS.IN;

  var status, nsec;

  var nsecRRset = response.findRRset(qname, consts.NAME_TO_QTYPE.NSEC, qclass, "authority");
  if (nsecRRset !== null) {
    status = verifySRRset(nsecRRset, keyRRset);
    if (status !== SECURITY_STATUS.SECURE) {
      return new utils.JustifiedSecStatus(SECURITY_STATUS.BOGUS, "NSEC RRset for the referral did not verify.");
    }

    nsec = nsecRRset.first();
    status = nsecProvesNoDS(nsec, qname);
    switch (status) {
      case SECURITY_STATUS.INSECURE:
        return new utils.JustifiedSecStatus(status, "NSEC RRset for the referral proved not a delegation point");
      case SECURITY_STATUS.SECURE:
        return new utils.JustifiedSecStatus(status, "NSEC RRset for the referral proved no DS.");
      default:
        return new utils.JustifiedSecStatus(status, "NSEC RRset for the referral did not prove no DS.");
    }
  }

  var ndp = new utils.NsecProvesNodataResponse();
  var ce = null, hasValidNSEC = false, wcNsec = null;
  nsecRRset = response.getSectionRRsets("authority", consts.NAME_TO_QTYPE.NSEC);
  for (var i = 0; i < nsecRRset.length; i++) {
    status = verifySRRset(nsecRRset, keyRRset);
    if (status !== SECURITY_STATUS.SECURE) {
      return new utils.JustifiedSecStatus(status, "NSEC for empty non-terminal did not verify.");
    }

    nsec = nsecRRset.first();
    ndp = nsecProvesNodata(nsec, qname, consts.NAME_TO_QTYPE.DS);
    if (ndp.result) {
      hasValidNSEC = true;
      if (ndp.wc != null && nsec.name == 'WILD') {
        wcNsec = nsec;
      }
    }

    if (nsecProvesNameError(nsec, qname, nsecRRset[i].getSignerName())) {
      ce = closestEncounter(qname, nsec);
    }
  }

  if (ndp.wc != null && (ce === null || ce != ndp.wc)) {
    hasValidNSEC = false;
  }

  if (hasValidNSEC) {
    if (ndp.wc !== null) {
      status = nsecProvesNoDS(wcNsec, qname);
      return new utils.JustifiedSecStatus(status, "NSEC for wildcard does not prove absence of DS.");
    }

    return new utils.JustifiedSecStatus(SECURITY_STATUS.INSECURE, "NSEC for empty non-terminal proved no DS.");
  }

  return new utils.JustifiedSecStatus(SECURITY_STATUS.UNCHECKED, "NSEC proof did not conclusively point to DS or no DS.");
};

var nsecProvesNameError = exports.nsecProvesNameError = function (nsec, qname, signerName) {

  var owner = dnsname.newNameFromString(nsec.name.toString());
  var next = dnsname.newNameFromString(nsec.next.toString());
  qname = dnsname.newNameFromString(qname.toString());

  if (qname.equals(owner)) {
    return false;
  }

  if (!next.subdomain(signerName)) {
    return false;
  }

  if (qname.subdomain(owner)) {
    if (nsec.hasType(consts.NAME_TO_QTYPE.DNAME)) {
      return false;
    }
    if (nsec.hasType(consts.NAME_TO_QTYPE.NS) && !nsec.hasType(consts.NAME_TO_QTYPE.SOA)) {
      return false;
    }
  }

  if (owner.equals(next)) {
    if (utils.strictSubdomain(qname, next)) {
      return true;
    }
  } else if (owner.compareTo(next) > 0) {
    if (owner.compareTo(qname) < 0 && utils.strictSubdomain(qname, next)) {
      return true;
    }
  } else {
    if (owner.compareTo(qname) < 0 && qname.compareTo(next) < 0) {
      return true;
    }
  }

  return false;
};

var longestCommonName = function (d1, d2) {
  var domain1 = dnsname.newNameFromString(d1.toString());
  var domain2 = dnsname.newNameFromString(d2.toString());

  var l = Math.min(domain1.labels(), domain2.labels());
  domain1 = dnsname.newNameRemoveLabels(domain1, domain1.labels() - l);
  domain2 = dnsname.newNameRemoveLabels(domain2, domain2.labels() - l);

  for (var i = 0; i < l - 1; i++) {
    var ns1 = dnsname.newNameRemoveLabels(domain1, i);
    if (ns1.equals(dnsname.newNameRemoveLabels(domain2, i)))
      return ns1;
  }

  return dnsname.root;
};

var closestEncounter = function (domain, nsec) {
  var n1 = longestCommonName(domain, nsec.name);
  var n2 = longestCommonName(domain, nsec.next);

  return (n1.labels() > n2.labels()) ? n1 : n2;
};

var nsecProvesNoWC = exports.nsecProvesNoWC = function (nsec, qname, signerName) {

  qname = dnsname.newNameFromString(qname.toString());

  var qnameLabels = qname.labels();
  var ce = closestEncounter(qname, nsec);
  var ceLabels = ce.labels();

  for (var i = qnameLabels - ceLabels; i > 0; i--) {
    var wcName = qname.wild(i);
    if (nsecProvesNameError(nsec, wcName, signerName)) {
      return true;
    }
  }
  return false;
};

var classifyResponse = exports.classifyResponse = function (response) {

  if (response.getRcode() == consts.NAME_TO_RCODE.NOTFOUND && response.getCount("answer") === 0) {
    return RESPONSE_CLASSIFICATION.NAMEERROR;
  }

  if (response.getCount("answer") === 0) {
    return RESPONSE_CLASSIFICATION.NODATA;
  }

  if (response.getQuestion().type == consts.NAME_TO_QTYPE.ANY) {
    return RESPONSE_CLASSIFICATION.ANY;
  }

  var hadCname = false;
  var answerRRsets = response.getSectionRRsets("answer");
  for (var i = 0; i < answerRRsets.length; i++) {
    if (answerRRsets[i].getType() == response.getQuestion().type) {
      return RESPONSE_CLASSIFICATION.POSITIVE;
    }

    if (answerRRsets[i].getType() == consts.NAME_TO_QTYPE.CNAME || answerRRsets[i].getType() == consts.NAME_TO_QTYPE.DNAME) {
      hadCname = true;
      if (response.getQuestion().type == consts.NAME_TO_QTYPE.DS) {
        return RESPONSE_CLASSIFICATION.CNAME;
      }
    }
  }

  if (hadCname) {
    if (response.getRcode() == consts.NAME_TO_RCODE.NOTFOUND) {
      return RESPONSE_CLASSIFICATION.CNAME_NAMEERROR;
    } else {
      return RESPONSE_CLASSIFICATION.CNAME_NODATA;
    }
  }

  return RESPONSE_CLASSIFICATION.NODATA;
};

var verifyNewDNSKEYs = exports.verifyNewDNSKEYs = function (dnskeyRRset, dsRRset, badKeyTtl) {

  var ke;
  if (!atLeastOneDigestSupported(dsRRset)) {
    ke = KeyEntry.newNullKeyEntry(dsRRset.name, dsRRset.record.class, dsRRset.record.ttl);
    ke.badReason = "No supported digest ID for DS for " + dsRRset.name;
    return ke;
  }

  if (!atLeastOneSupportedAlgorithm(dsRRset)) {
    ke = KeyEntry.newNullKeyEntry(dsRRset.name, dsRRset.record.class, dsRRset.record.ttl);
    ke.badReason = "No supported algorithm ID on DS for " + dsRRset.name;
    return ke;
  }

  var favoriteDigestID = favoriteDSDigestID(dsRRset);

  var dsrrs = dsRRset.rrs();
  for (var i = 0; i < dsrrs.length; i++) {
    var ds = dsrrs[i];
    if (ds.digestType != favoriteDigestID) continue;

    var dnskeyrrs = dnskeyRRset.rrs();
    DNSKEY: for (var j = 0; j < dnskeyrrs.length; j++) {
      var dnskey = dnskeyrrs[j];
      if (ds.keytag != utils.getDnskeyFootprint(dnskey) || ds.algorithm != dnskey.algorithm) {
        continue;
      }

      var keyDigest = {
        name: ".", type: consts.NAME_TO_QTYPE.DS,
        dclass: consts.NAME_TO_QCLASS.IN,
        ttl: 0,
        digestType: ds.digestType,
        digest: utils.generateDSDigest(dnskey, ds.digestType)
      };
      var keyHash = keyDigest.digest;
      var dsHash;
      if (typeof ds.digest === "string") {
        dsHash = ds.digest;
      } else if (typeof ds.digest.buffer !== "undefined") {
        dsHash = conv(ds.digest.buffer, {in: 'buffer', out: 'hex'});
      }

      if (keyHash.length !== dsHash.length) continue;

      if (keyHash.toUpperCase() !== dsHash.toUpperCase()) {
        continue DNSKEY;
      }

      var res = utils.verifyRRsetAgainstDnskey(dnskeyRRset, dnskey);
      if (res === SECURITY_STATUS.SECURE) {
        //console.log("DS Matched DNSKEY");
        dnskeyRRset.securityStatus = SECURITY_STATUS.SECURE;
        return KeyEntry.newKeyEntry(dnskeyRRset);
      }
    }
  }

  var badKey = KeyEntry.newBadKeyEntry(dsRRset.getName(), dsRRset.getDClass(), badKeyTtl);
  return badKey;
};

var verifySRRset = exports.verifySRRset = function (rrset, keyRRset) {
  var rrsetName = rrset.getName() + "/" + consts.QTYPE_TO_NAME[rrset.getType()] + "/" + consts.QCLASS_TO_NAME[rrset.getDClass()];

  if (rrset.securityStatus === SECURITY_STATUS.SECURE) {
    //console.log("verifySRRset: rrset <" + rrsetName + "> previously found to be SECURE");
    return SECURITY_STATUS.SECURE;
  }

  var verifier = new DNSSECVerifier();
  var status = verifier.verifyRRSet(rrset, keyRRset);
  if (status !== SECURITY_STATUS.SECURE) {
    status = SECURITY_STATUS.BOGUS;
  }

  rrset.securityStatus = status;
  return status;
};

var favoriteDSDigestID = exports.favoriteDSDigestID = function (dsset) {
  var max = 0;
  var dsrrs = dsset.rrs();
  for (var i = 0; i < dsrrs.length; i++) {
    var r = dsrrs[i];
    if (r.digestType > max && isDigestSupported(r.digestType) && isAlgorithmSupported(r.algorithm)) {
      max = r.digestType;
    }
  }
  return max;
};

var rrsetWildcard = exports.rrsetWildcard = function (rrset) {
  var sigs = rrset.sigs();
  var rrsig = sigs[0];

  for (var i = 1; i < sigs.length; i++) {
    if (sigs[i].labels != rrsig.labels) {
      throw "failed.wildcard.label_count_mismatch";
    }
  }

  var wn = rrset.getName();

  if (rrset.getName().isWild()) {
    wn = dnsname.newNameRemoveLabels(wn, 1);
  }

  var labelDiff = (wn.labels() - 1) - rrsig.labels;
  if (labelDiff > 0) {
    return wn.wild(labelDiff);
  }

  return null;
};