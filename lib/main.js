'use strict';

var assert = require('assert'),
    consts = require('native-dns-packet').consts,
    dgram = require('dgram'),
    dnsname = require('./name'),
    EventEmitter = require('events').EventEmitter,
    KeyCache = require('./keycache').KeyCache,
    KeyEntry = require('./keyentry'),
    n3valUtils = require('./n3valutils'),
    NDP = require('native-dns-packet'),
    net = require('net'),
    os = require('os'),
    RESPONSE_CLASSIFICATION = require('./valutils').RESPONSE_CLASSIFICATION,
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    SMessage = require('./smessage').SMessage,
    SRRSet = require('./srrset').SRRSet,
    TrustAnchorStore = require('./trust-anchor-store').TrustAnchorStore,
    udpProvider = require('./udp'),
    util = require('util'),
    utils = require('./utils'),
    valutils = require('./valutils');

var DEFAULT_TA_BAD_KEY_TTL = 60;

var random_integer = function () {
  return Math.floor(Math.random() * 50000 + 1);
};

/*********************************************************************
 * DNSSECRequest
 *
 * Holds all record lookups and the UDP socket handling DNS requests
 **********************************************************************/
var DNSSECQuery = exports.DNSSECQuery = function (opts) {

  if (!(this instanceof DNSSECQuery)) return new DNSSECQuery(opts);

  assert(typeof opts.name != 'undefined', 'DNSSECRequest requires "name"');
  assert(typeof opts.type != 'undefined', 'DNSSECRequest requires "type"');
  if (opts.name[opts.name.length - 1] != '.')
    opts.name = opts.name + '.';

  var qtype = opts.type || NDP.consts.NAME_TO_QTYPE.A;
  if (typeof(qtype) === 'string' || qtype instanceof String)
    qtype = consts.nameToQtype(qtype.toUpperCase());

  if (!qtype || typeof(qtype) !== 'number')
    throw new Error("Question type must be defined and be valid");

  this.initialServer = opts.server || "8.8.8.8";

  //this.records = new RRStore();
  this._socket = null;
  this.question = {
    name: opts.name,
    type: qtype
  };
};

/*********************************************************************
 * DNSSECResolver
 *
 * Handles DNS Requests and DNSSEC Validation
 **********************************************************************/
var DNSSECResolver = exports.DNSSECResolver = function (query) {
  EventEmitter.call(this);

  if (!(this instanceof DNSSECResolver)) return new DNSSECQuery(DNSSECResolver);

  this.initialQuery = query;
  this.initialQuestion = query.question;
  this.keyCache = new KeyCache();
  this.query = {};
  this.question = this.initialQuestion;
  this.trustAnchors = new TrustAnchorStore();
  this.requestMap = {};
  this.completedFired = false;
  this.debug = false;

};
util.inherits(DNSSECResolver, EventEmitter);

DNSSECResolver.prototype.log = function(message) {
  if (this.debug) {
      console.log(message);
  }
};

DNSSECResolver.prototype.loadTrustAnchors = function (records) {
  var zone = utils.parseBindFormat(records);
  var sortedRecords = zone.records.sort(utils.recordComparator);

  var currentRRset = new SRRSet();
  for (var i = 0; i < sortedRecords.length; i++) {
    var record = sortedRecords[i];
    if (record.type !== consts.NAME_TO_QTYPE.DNSKEY && record.type !== consts.NAME_TO_QTYPE.DS) {
      continue;
    }

    if (currentRRset.size() === 0) {
      currentRRset.addRR(record);
      continue;
    }

    if (currentRRset.getName() == record.name && currentRRset.getType() == record.type && currentRRset.getDClass() == record.dclass) {
      currentRRset.addRR(record);
      continue;
    }

    this.trustAnchors.store(currentRRset);
    currentRRset = new SRRSet();
    currentRRset.addRR(record);
  }

  if (currentRRset.size() > 0) {
    this.trustAnchors.store(currentRRset);
  }
};

DNSSECResolver.prototype.resolve = function (name, type, callback) {
  var self = this;
  if (typeof this._socket === "undefined") {
    this._socket = udpProvider.createSocket('udp4', function (msg) {
        self.handle(self, msg);
      });
    // this._socket = dgram.createSocket('udp4');
    // this._socket.on('message', function (msg) {
    //   self.handle(self, msg);
    // });
  }

  var opts = {
    server: this.initialQuery.initialServer,
    resolver: this
  };

  if (typeof name === "undefined" && typeof type === "undefined") {
    opts.name = this.initialQuestion.name;
    opts.type = this.initialQuestion.type;
  } else {
    opts.name = name;
    opts.type = type;
  }

  opts.callback = callback || null;
  this.send(opts);
};

DNSSECResolver.prototype.handle = function (resolver, msg) {

  this.log("\n\nReceived Response Packet:\n-------------------------");

  var packet = NDP.parse(msg);
  var origQuery = this.query;

  // Unset AD Flags
  packet.header.ad = 0;

  // If CD Flag is set, return the original question's response
  if (packet.header.cd && packet.question.name == packet.question[0].name && resolver.question.type == packet.question[0].type) {
    resolver.emit('complete', packet);
    return;
  }

  // Add Newly Received Answer Records
  this.log("QUESTION: " + JSON.stringify(packet.question[0]));

  var i;
  for (i = 0; i < packet.answer.length; i++) {
    if (packet.answer[i].name !== "") {
      this.log("ANSWER[" + i + "]: " + JSON.stringify(packet.answer[i]));
    }
  }

  for (i = 0; i < packet.additional.length; i++) {
    if (packet.additional[i].name !== "") {
      this.log("ADDITIONAL[" + i + "]: " + JSON.stringify(packet.additional[i]));
    }
  }

  for (i = 0; i < packet.authority.length; i++) {
    if (packet.authority[i].name !== "") {
      this.log("AUTHORITY[" + i + "]: " + JSON.stringify(packet.authority[i]));
    }
  }


  // If the original question is for an RRSIG, return the RRSIG itself without any processing (there are no sigs on sigs)
  //var rrsigSet = origQuery.records.get(resolver.question.name, consts.NAME_TO_QTYPE.RRSIG);
  //assert(rrsig, "No RRSIG Present on Request, Unable to Validate");

  var response = new SMessage(packet);
  var requestData = this.requestMap[response.header.id];
  var request = new SMessage(requestData.request);

  if (packet.question[0].name == resolver.question.name && resolver.question.type === consts.NAME_TO_QTYPE.RRSIG && packet.question[0].type == resolver.question.type && packet.header.rcode === consts.NAME_TO_RCODE.NOERROR) {
    this.processFinishedState(request, response);
  }


  // Handle callbacks (used for DNSSEC Chain Traversal)
  if (requestData.callback !== null && typeof requestData.callback === "function") {
    requestData.callback(request, response);
  }

  if (request.getQuestion().name !== this.initialQuestion.name && request.getQuestion().type !== this.initialQuestion.type) {
    return;
  }

  this.on('chainComplete', function (ke) {
    this.processValidate(request, response);
  });

  this.on('processFinished', function (returnedResponse, securityStatus) {
    var finishedResponse = returnedResponse || response;
    if(securityStatus) {
      finishedResponse.securityStatus = securityStatus;
    }

    // Only process the finished state if the request's question matches the initial response
    if(finishedResponse.getQuestion().name == this.initialQuestion.name && finishedResponse.getQuestion().type == this.initialQuestion.type) {
      this.processFinishedState(request, finishedResponse);
    }
  });

  var validated = resolver.processValidate(request, response);

};

DNSSECResolver.prototype.processValidate = function (request, response) {

  var subtype = valutils.classifyResponse(response);

  switch (subtype) {
    case RESPONSE_CLASSIFICATION.POSITIVE:
    case RESPONSE_CLASSIFICATION.CNAME:
    case RESPONSE_CLASSIFICATION.ANY:
      this.log("Validating a positive response");
      this.validatePositiveResponse(request, response);
      break;

    case RESPONSE_CLASSIFICATION.NODATA:
      this.log("Validating a nodata response");
      this.validateNodataResponse(request, response);
      break;

    case RESPONSE_CLASSIFICATION.CNAME_NODATA:
      this.log("Validating a CNAME_NODATA response");
      this.validatePositiveResponse(request, response);
      if (response.securityStatus !== SECURITY_STATUS.INSECURE) {
        response.securityStatus = SECURITY_STATUS.UNCHECKED;
        this.validateNodataResponse(request, response);
      }
      break;

    case RESPONSE_CLASSIFICATION.NAMEERROR:
      this.log("Validating a nxdomain response");
      this.validateNameErrorResponse(request, response);
      break;

    case RESPONSE_CLASSIFICATION.CNAME_NAMEERROR:
      this.log("Validating a cname_nxdomain response");
      this.validatePositiveResponse(request, response);
      if (response.securityStatus !== SECURITY_STATUS.INSECURE) {
        response.securityStatus = SECURITY_STATUS.UNCHECKED;
        this.validateNameErrorResponse(request, response);
      }
      break;

    default:
      response.setBogus("Response subtype is " + subtype + " and thus cannot be validated.");
  }
};

DNSSECResolver.prototype.processFinishedState = function (request, response) {

  if(this.completedFired) {
    return;
  } else {
    this.completedFired = true;
  }

  var securityStatus = response.securityStatus;
  var reason = response.bogusReason;

  switch (response.securityStatus) {
    case SECURITY_STATUS.BOGUS:
      var code = response.getHeader().rcode;
      if ([consts.NAME_TO_RCODE.NOERROR, consts.NAME_TO_RCODE.NOTFOUND, consts.NAME_TO_RCODE.YXDOMAIN].indexOf(code) !== -1) {
        code = consts.NAME_TO_RCODE.SERVFAIL;
      }

      var m = new SMessage();
      m.getHeader().id = request.getHeader().id;
      m.getHeader().rcode = code;
      m.getHeader().qr = 1;
      response = m;
      break;

    case SECURITY_STATUS.SECURE:
      response.getHeader().ad = 1;
      break;

    case SECURITY_STATUS.UNCHECKED:
    case SECURITY_STATUS.INSECURE:
      break;
    default:
      throw "Unexpected Security Status";
  }

  response.securityStatus = securityStatus;
  response.bogusReason = reason;
  this.emit('complete', response);
};

DNSSECResolver.prototype.validatePositiveResponse = function (request, response) {

  var i, wcs = {}, nsec3s = [], nsecs = [];
  var qtype = request.getQuestion().type;

  if (!this.validateAnswerAndGetWildcards(response, qtype, wcs)) {
    return;
  }

  var keyRRset = new SRRSet();
  var sections;
  if (qtype === consts.NAME_TO_QTYPE.ANY) {
    sections = ["answer", "authority"];
  } else {
    sections = ["authority"];
  }

  for (i = 0; i < sections.length; i++) {

    var rrsets = response.getSectionRRsets(sections[i]);

    for (var j = 0; j < rrsets.length; j++) {
      var ke = this.prepareFindKey(rrsets[j]);
      if (!this.processKeyValidate(response, rrsets[i].getSignerName(), ke)) {
        return;
      }

      keyRRset = ke.rrset;
      var securityStatus = valutils.verifySRRset(rrsets[j], keyRRset);
      if (securityStatus != SECURITY_STATUS.SECURE) {
        response.setBogus("Positive response has failed AUTHORITY rrset: " + rrsets[j].toString());
      }

      if (Object.keys(wcs).length > 0) {
        if (rrsets[j].getType() === consts.NAME_TO_QTYPE.NSEC) {
          nsecs.push(rrsets[j]);
        } else if (rrsets[j].getType() === consts.NAME_TO_QTYPE.NSEC3) {
          nsec3s.push(rrsets[j]);
        }
      }
    }
  }

  if (Object.keys(wcs).length > 0) {
    for (var wc in wcs) {
      if(!wcs.hasOwnProperty(wc)) {
        continue;
      }
      var wcNsecOk = false;
      for (i = 0; i < nsecs.length; i++) {
        var nsec = nsecs[i];
        if (valutils.nsecProvesNameError(nsec, wc, nsec.getSignerName())) {
          var nsecwc = valutils.nsecWildcard(wc, nsec);
          if (wcs[wc] == nsecwc) {
            wcNsecOk = true;
            break;
          }

        }
      }

      if (!wcNsecOk && nsec3s.length > 0) {
        if (n3valUtils.allNSEC3sIgnoreable(nsec3s, this.keyCache)) {
          response.securityStatus = SECURITY_STATUS.INSECURE;
          response.bogusReason = "All NSEC3s were validated but ignored due to unknown algorithms or invalid iteration counts.";
          return this.emit('processFinished', response);
        }

        var status = n3valUtils.proveWildcard(nsec3s, wc, nsec3s[0].getSignerName(), wcs[wc]);
        if (status === SECURITY_STATUS.INSECURE) {
          response.securityStatus = status;
          return this.emit('processFinished', response);
        } else if (status === SECURITY_STATUS.SECURE) {
          wcNsecOk = true;
        }
      }

      if (!wcNsecOk) {
        response.setBogus("Positive response was wildcard expansion and did not prove original data did not exist or wasn't generated by the correct wildcard.");
        return this.emit('processFinished', response);
      }
    }
  }

  response.securityStatus = SECURITY_STATUS.SECURE;
  return this.emit('processFinished', response);
};

DNSSECResolver.prototype.validateAnswerAndGetWildcards = function (response, qtype, wcs) {
  var dname = null;
  var rrsets = response.getSectionRRsets("answer");
  for (var i = 0; i < rrsets.length; i++) {
    var set = rrsets[i];

    if (set.getType() == consts.NAME_TO_QTYPE.CNAME && dname != null) {
      if (set.size() > 1) {
        response.setBogus("Synthesized CNAME RRset has multiple records - that doesn't make sense.");
        return false;
      }

      var cname = set.first();
      var expected = utils.nameRelativize(cname.name, dname.name) + dname.data;
      if (expected != cname.data) {
        response.setBogus("Synthesized CNAME target (" + cname.data + ") included in answer doesn't match DNAME synthesis rules (expected " + expected + ").");
        return false;
      }

      set.securityStatus = SECURITY_STATUS.SECURE;
      dname = null;
      continue;
    }

    var ke = this.prepareFindKey(set);
    if (ke == null) return false;
    if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
      return false;
    }

    var status = valutils.verifySRRset(set, ke.getRRset());
    if (status != SECURITY_STATUS.SECURE) {
      response.setBogus("Positive response has failed ANSWER rrset: " + set.toString());
      return false;
    }

    var wc = null;
    try {
      wc = valutils.rrsetWildcard(set);
    } catch (err) {
      response.setBogus(err + ": " + set.getName());
      return false;
    }

    if (wc !== null) {
      // RFC 4592, Section 4.4 does not allow wildcarded DNAMEs
      if (set.getType() == consts.NAME_TO_QTYPE.DNAME) {
        response.setBogus("Illegal DNAME (" + set.getName() + " is from a wildcard expansion).");
        return false;
      }

      wcs[set.getName()] = wc;
    }

    if (qtype !== consts.NAME_TO_QTYPE.DNAME && set.getType() === consts.NAME_TO_QTYPE.DNAME) {
      dname = set.first();
    }
  }

  return true;
};

DNSSECResolver.prototype.prepareFindKey = function (rrset) {
  var state = new utils.FindKeyState();
  state.signerName = rrset.getSignerName() || rrset.getName();
  state.qclass = rrset.getDClass();

  var trustAnchorRRset = this.trustAnchors.find(state.signerName, rrset.getDClass());
  if (trustAnchorRRset === null) {
    return KeyEntry.newNullKeyEntry(rrset.getSignerName(), rrset.getDClass(), DEFAULT_TA_BAD_KEY_TTL);
  }

  state.keyEntry = this.keyCache.find(state.signerName, rrset.getDClass());
  if (state.keyEntry === null || (!state.keyEntry.getName().equals(state.signerName) && state.keyEntry.isGood())) {
    state.dsRRset = trustAnchorRRset;
    state.keyEntry = null;
    state.currentDSKeyName = dnsname.newNameRemoveLabels(trustAnchorRRset.getName(), 1);
    this.processFindKey(state);
  }

  return state.keyEntry;
};

DNSSECResolver.prototype.processFindKey = function (state) {
  var qclass = state.qclass;

  var targetKeyName;
  if (typeof state.signerName === "string") {
    targetKeyName = dnsname.newNameFromString(state.signerName);
  } else {
    targetKeyName = state.signerName;
  }
  var currentKeyName = "";
  if (state.keyEntry != null) {
    currentKeyName = state.keyEntry.getName();
  }

  if (state.currentDSKeyName != null) {
    currentKeyName = state.currentDSKeyName;
    state.currentDSKeyName = null;
  }

  if (currentKeyName == targetKeyName) {
    return;
  }

  if (state.emptyDSName != null) {
    currentKeyName = state.emptyDSName;
  }

  // Calculate the next lookup name.
  var targetLabels = targetKeyName.labels();
  var currentLabels = currentKeyName.labels();
  var l = targetLabels - currentLabels - 1;

  if (l < 0) {
    this.emit('chainComplete', state.keyEntry);
    return;
  }

  var nextKeyName = dnsname.newNameRemoveLabels(targetKeyName, l);
  this.log("findKey: targetKeyName = " + targetKeyName + ", currentKeyName = " + currentKeyName + ", nextKeyName = " + nextKeyName);

  if (state.dsRRset === null || !state.dsRRset.getName().equals(nextKeyName)) {
    this.resolve(nextKeyName.toString(), consts.NAME_TO_QTYPE.DS, function (request, response) {
      //this.processDSResponse({name: localNextKeyName, type: consts.NAME_TO_QTYPE.DS}, packet, state);
      this.resolver.processDSResponse(request, response, state);
    });
    return;
  }

  this.resolve(state.dsRRset.getName().toString(), consts.NAME_TO_QTYPE.DNSKEY, function (request, response) {
    //this.processDNSKEYResponse({name: state.dsRRset.getName().toString(), type: consts.NAME_TO_QTYPE.DNSKEY}, packet, state);
    this.resolver.processDNSKEYResponse(request, response, state);
  });

};

DNSSECResolver.prototype.processKeyValidate = function (response, signerName, keyEntry) {

  if (signerName == null) {
    this.log("processKeyValidate: no signerName");

    if (keyEntry == null) {
      response.setBogus("KeyEntry not yet available, unable to process key validation");
      return false;
    }

    if (keyEntry.isNull()) {
      var noSignerKENullReason = keyEntry.badReason;
      if (noSignerKENullReason == null) {
        noSignerKENullReason = "Unsigned response was proved to be validly INSECURE";
      }
      response.securityStatus = SECURITY_STATUS.INSECURE;
      response.setBogus(noSignerKENullReason);
      return false;
    }

    if (keyEntry.isGood()) {
      response.setBogus("Could not validate RRset due to missing signature.");
      return false;
    }

    response.setBogus("Could not establish validation of INSECURE status of unsigned response. Reason: " + keyEntry.badReason);
    return false;
  }

  if (keyEntry == null) {
    response.setBogus("KeyEntry not yet available, unable to process key validation");
    return false;
  }

  if (keyEntry.isBad) {
    response.setBogus("Could not establish a chain of trust to keys for [" + keyEntry.getName() + "]. Reason: " + keyEntry.badReason);
    return false;
  }

  if (keyEntry.isNull()) {
    var keNullReason = keyEntry.badReason;
    if (keNullReason == null) {
      keNullReason = "Verified that response is INSECURE";
    }
    response.securityStatus = SECURITY_STATUS.INSECURE;
    response.badReason = keNullReason;
    return false;
  }

  return true;
};

DNSSECResolver.prototype.validateNameErrorResponse = function (request, response) {
  var qname = request.getQuestion().name;
  var answerSectionRRsets = response.getSectionRRsets("answer");
  for (var i = 0; i < answerSectionRRsets.length; i++) {
    if (answerSectionRRsets[i].securityStatus !== SECURITY_STATUS.SECURE) {
      response.setBogus("CNAME_NAMEERROR response has failed ANSWER rrset: " + answerSectionRRsets[i].getName().toString());
      return;
    }

    if (answerSectionRRsets[i].getType() === consts.NAME_TO_QTYPE.CNAME)
      qname = answerSectionRRsets[i].first().data;
  }

  var hasValidNSEC = false;
  var hasValidWCNSEC = false;
  var nsec3s = [];
  var nsec3Signer = null;
  var keyRRset;

  var authRRSets = response.getSectionRRsets("authority");
  for (i = 0; i < authRRSets.length; i++) {
    var set = authRRSets[i];
    var ke = this.prepareFindKey(set);
    if (!this.processKeyValidate(response, set.getSignerName(), ke))
      return;

    keyRRset = ke.getRRset();
    var status = valutils.verifySRRset(set, keyRRset);
    if (status !== SECURITY_STATUS.SECURE) {
      response.setBogus("NameError response has failed AUTHORITY rrset: " + set.getName().toString());
      return;
    }

    if (set.getType() === consts.NAME_TO_QTYPE.NSEC) {
      var nsec = set.first();
      if (valutils.nsecProvesNameError(nsec, qname, set.getSignerName()))
        hasValidNSEC = true;

      if (valutils.nsecProvesNoWC(nsec, qname, set.getSignerName()))
        hasValidWCNSEC = true;
    }

    if (set.getType() === consts.NAME_TO_QTYPE.NSEC3) {
      nsec3s.push(set);
      nsec3Signer = set.getSignerName();
    }
  }

  n3valUtils.stripUnknownAlgNSEC3s(nsec3s);
  if ((!hasValidNSEC || !hasValidWCNSEC) && nsec3s.length > 0) {
    this.log("Validating nxdomain: using NSEC3 records");

    if (n3valUtils.allNSEC3sIgnoreable(nsec3s, this.keyCache)) {
      response.securityStatus = SECURITY_STATUS.INSECURE;
      response.badReason = "All NSEC3s were validated but ignored due to unknown algorithms or invalid iteration counts.";
      return;
    }

    var pneStatus = n3valUtils.proveNameError(nsec3s, qname, nsec3Signer);
    if (pneStatus !== SECURITY_STATUS.SECURE) {
      response.securityStatus = pneStatus;
      if (pneStatus === SECURITY_STATUS.INSECURE)
        response.badReason = "NSEC3 proofed that the target domain is under opt-out, response is insecure.";
      else
        response.badReason = "NSEC3 failed to proof the name error.";

      return;
    }

    hasValidNSEC = true;
    hasValidWCNSEC = true;
  }

  if (!hasValidNSEC) {
    response.setBogus("NameError response has failed to prove that " + response.getQuestion().name + " does not exist.");
    return;
  }

  if (!hasValidWCNSEC) {
    response.setBogus("NameError response has failed to prove that the covering wildcard does not exist.");
    return;
  }

  this.log("Successfully validated NAME ERROR response.");
  response.securityStatus = SECURITY_STATUS.SECURE;
  return this.emit('processFinished', response);
};

DNSSECResolver.prototype.validateNodataResponse = function (request, response) {
  var qname = request.getQuestion().name;
  var qtype = request.getQuestion().type;

  var rrsets = response.getSectionRRsets("answer");
  var i;

  for (i = 0; i < rrsets.length; i++) {
    if (rrsets[i].securityStatus !== SECURITY_STATUS.SECURE) {
      response.setBogus("CNAME_NODATA response has failed ANSWER rrset: " + rrsets[i].getName());
      return;
    }

    if (rrsets[i].getType() === consts.NAME_TO_QTYPE.CNAME) {
      qname = rrsets[i].first().data;
    }
  }

  var hasValidNSEC = false;
  var ce = null;
  var ndp = new utils.NsecProvesNodataResponse();
  var nsec3s = [];
  var nsec3Signer = null;

  var authorityRRset = response.getSectionRRsets("authority");
  for (i = 0; i < authorityRRset.length; i++) {
    var set = authorityRRset[i];
    var ke = this.prepareFindKey(set);
    if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
      return;
    }

    var status = valutils.verifySRRset(set, ke.getRRset());
    if (status != SECURITY_STATUS.SECURE) {
      response.setBogus("NODATA response has failed AUTHORITY rrset: " + set.getName());
      return this.emit('processFinished', response);
    }

    if (set.getType() === consts.NAME_TO_QTYPE.NSEC) {
      var nsec = set.first();
      ndp = valutils.nsecProvesNodata(nsec, qname, qtype);
      if (ndp.result) {
        hasValidNSEC = true;
      }

      if (valutils.nsecProvesNameError(nsec, qname, set.getSignerName())) {
        ce = valutils.closestEncloser(qname, nsec);
      }
    }

    if (set.getType() === consts.NAME_TO_QTYPE.NSEC3) {
      nsec3s.push(set);
      nsec3Signer = set.getSignerName();
    }
  }

  if (ndp.wc !== null && (ce == null || (!ce.equals(ndp.wc) && !qname.equals(ce)))) {
    hasValidNSEC = false;
  }

  n3valUtils.stripUnknownAlgNSEC3s(nsec3s);
  if (!hasValidNSEC && nsec3s.length > 0) {
    if (n3valUtils.allNSEC3sIgnoreable(nsec3s, this.keyCache)) {
      response.setBogus("All NSEC3s were validated but ignored due to unknown algorithms or invalid iteration counts.");
      return this.emit('processFinished', response);
    }

    var pndStatus = n3valUtils.proveNodata(nsec3s, qname, qtype, nsec3Signer);
    if (pndStatus === SECURITY_STATUS.INSECURE) {
      response.securityStatus = SECURITY_STATUS.INSECURE;
      return this.emit('processFinished', response);
    }

    hasValidNSEC = pndStatus == SECURITY_STATUS.SECURE;
  }

  if (!hasValidNSEC) {
    response.setBogus("NODATA response failed to prove NODATA status with NSEC/NSEC3");
    this.log("Failed NODATA for " + qname);
    return this.emit('processFinished', response);
  }

  this.log("Successfully validated NODATA Response");
  response.securityStatus = SECURITY_STATUS.SECURE;
  return this.emit('processFinished', response);
};

DNSSECResolver.prototype.processDSResponse = function (request, response, state) {
  var qname = request.getQuestion().name;

  state.emptyDSName = null;
  state.dsRRset = null;

  var dsKE = this.dsResponseToKE(response, request, state.keyEntry.getRRset());
  if (dsKE == null) {
    state.emptyDSName = qname;
  } else if (dsKE.isGood()) {
    state.dsRRset = dsKE.getRRset();
    state.currentDSKeyName = dnsname.newNameRemoveLabels(dsKE.getRRset().getName(), 1);
    this.keyCache.store(dsKE);
  } else {
    state.keyEntry = dsKE;
    if (dsKE.isNull()) {
      this.keyCache.store(dsKE);
    }
    this.emit('processFinished', undefined, SECURITY_STATUS.INSECURE);
    return;
  }

  return this.processFindKey(state);
};

DNSSECResolver.prototype.processDNSKEYResponse = function (request, response, state) {
  var qname = request.getQuestion().name;
  var qclass = consts.NAME_TO_QCLASS.IN;

  var dnskeyRRset = response.findAnswerRRset(qname, consts.NAME_TO_QTYPE.DNSKEY, qclass);
  if (dnskeyRRset === null) {
    // If the DNSKEY rrset was missing, this is the end of the line.
    state.keyEntry = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
    state.keyEntry.setBadReason("Missing DNSKEY RRset in response to DNSKEY query for " + qname + ".");
    return;
  }

  state.keyEntry = valutils.verifyNewDNSKEYs(dnskeyRRset, state.dsRRset, DEFAULT_TA_BAD_KEY_TTL);

  // If the key entry isBad or isNull, then we can move on to the next
  // state.
  if (!state.keyEntry.isGood()) {
    return;
  }

  // The DNSKEY validated, so cache it as a trusted key rrset.
  this.keyCache.store(state.keyEntry);

  // If good, we stay in the FINDKEY state.
  this.processFindKey(state);
};

DNSSECResolver.prototype.dsResponseToKE = function (response, request, keyRRset) {
  var qname = request.getQuestion().name;
  var qclass = consts.NAME_TO_QCLASS.IN;

  var status;
  var subtype = valutils.classifyResponse(response);

  var bogusKE = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
  switch (subtype) {
    case RESPONSE_CLASSIFICATION.POSITIVE:
      var dsRRset = response.findAnswerRRset(qname, consts.NAME_TO_QTYPE.DS, consts.NAME_TO_QCLASS.IN);
      status = valutils.verifySRRset(dsRRset, keyRRset);
      if (status != SECURITY_STATUS.SECURE) {
        bogusKE.setBadReason("DS rrset in DS response did not verify");
        return bogusKE;
      }

      if (!valutils.atLeastOneSupportedAlgorithm(dsRRset)) {
        var nullKey = KeyEntry.newNullKeyEntry(qname, qclass, dsRRset.getTtl());
        nullKey.setBadReason("No supported algorithms in DS RRset for " + qname + ", treating as insecure.");
        return nullKey;
      }

        this.log("DS RRSet was good: " + qname);
      return KeyEntry.newKeyEntry(dsRRset);

    case RESPONSE_CLASSIFICATION.CNAME:
      var cnameRRset = response.findAnswerRRset(qname, consts.NAME_TO_QTYPE.CNAME, consts.NAME_TO_QCLASS.IN);
      status = valutils.verifySRRset(cnameRRset, keyRRset);
      if (status === SECURITY_STATUS.SECURE) {
        return null;
      }

      bogusKE.setBadReason("CNAME in DS response was not secure.");
      return bogusKE;

    case RESPONSE_CLASSIFICATION.NODATA:
    case RESPONSE_CLASSIFICATION.NAMEERROR:
      return this.dsResponseToKeForNodata(response, request, keyRRset);

    default:
      bogusKE.setBadReason("Encountered an unhandled type (" + subtype + ") of DS response, thus bogus.");
      return bogusKE;
  }
};

DNSSECResolver.prototype.dsResponseToKeForNodata = function (response, request, keyRRset) {
  var qname = request.getQuestion().name;
  var qclass = consts.NAME_TO_QCLASS.IN;
  var bogusKE = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);

  if (!valutils.hasSignedNsecs(response)) {
    bogusKE.setBadReason("No signed NSEC/NSEC3 records for query to " + qname + "/DS.");
    return bogusKE;
  }

  // Process Possible NSEC Records
  var status = valutils.nsecProvesNodataDsReply(request, response, keyRRset);
  switch (status.status) {
    case SECURITY_STATUS.SECURE:
      var nullKey = KeyCache.newNullKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
      nullKey.setBadReason("NSEC RRset for the referral proved no DS.");
      return nullKey;

    case SECURITY_STATUS.INSECURE:
      return null;

    case SECURITY_STATUS.BOGUS:
      bogusKE.setBadReason(status.reason);
      return bogusKE;

    default:
      // NSEC proof did not work, try NSEC3
      break;
  }

  // Process NSEC3 Records
  var nsec3RRsets = response.getSectionRRsets("authority", consts.NAME_TO_QTYPE.NSEC3);
  var nsec3s = [];
  var nsec3Signer = null;
  var nsec3ttl = -1;

  if (nsec3RRsets.length > 0) {
    for (var i = 0; i < nsec3RRsets.length; i++) {
      var sstatus = valutils.verifySRRset(nsec3RRsets[i], keyRRset);
      if (sstatus !== SECURITY_STATUS.SECURE) {
          this.log("Skipping Bad NSEC3");
        continue;
      }

      nsec3Signer = nsec3RRsets[i].getSignerName();
      if (nsec3ttl < 0 || nsec3RRsets[i].getTtl() < nsec3ttl) {
        nsec3ttl = nsec3RRsets[i].getTtl();
      }

      nsec3s.push(nsec3RRsets[i]);
    }

    switch (valutils.proveNoDs(nsec3s, qname, nsec3Signer)) {
      case SECURITY_STATUS.INSECURE:
          this.log("NSEC3s Proved No Delegation");
        return null;

      case SECURITY_STATUS.SECURE:
        var nullKeySec = KeyEntry.newNullKeyEntry(qname, qclass, nsec3ttl);
        nullKeySec.setBadReason("NSEC3s proved no DS.");
        return nullKeySec;

      default:
        bogusKE.setBadReason("NSEC3s proved bogus.");
        return bogusKE;
    }
  }

  bogusKE.setBadReason("Ran out of validation options, thus bogus.");
  return bogusKE;
};

DNSSECResolver.prototype.send = function (opts) {
  var buff, len;

  buff = new Buffer(4096);
  var dnssecQueryPacket = this.buildDnssecRequestPacket(opts);
  this.requestMap[dnssecQueryPacket.header.id] = opts;
  this.requestMap[dnssecQueryPacket.header.id].request = dnssecQueryPacket;
  len = NDP.write(buff, dnssecQueryPacket);
  this._socket.send(buff, 0, len, 53, opts.server);
};

DNSSECResolver.prototype.buildDnssecRequestPacket = function (opts) {

  var qtype;

  qtype = opts.type || consts.NAME_TO_QTYPE.A;
  if (typeof(qtype) === 'string' || qtype instanceof String)
    qtype = consts.nameToQtype(qtype.toUpperCase());

  if (!qtype || typeof(qtype) !== 'number')
    throw new Error("Question type must be defined and be valid");

  this.query.id = random_integer();

  return {
    answer: [],
    authority: [],
    additional: [],
    do: true,
    edns_options: [],
    edns_version: 0,
    header: {
      id: this.query.id,
      rd: 1
    },
    payload: 4096,
    question: [{
      name: opts.name,
      type: qtype,
      class: consts.NAME_TO_QCLASS.IN
    }],
    try_edns: true
  };
};

exports.SECURITY_STATUS = SECURITY_STATUS;