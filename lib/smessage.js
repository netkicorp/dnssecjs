var consts = require('native-dns-packet').consts,
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    SRRSet = require('./srrset').SRRSet,
    utils = require('./utils');

var MAX_FLAGS = 16;

var SMessage = function (packet) {

  if (!(this instanceof SMessage)) return new SMessage();

  this.header = {};
  this.question = null;
  this.optRecord = null;
  this.sections = {
    answer: [],
    authority: [],
    additional: []
  };
  this.securityStatus = SECURITY_STATUS.UNCHECKED;
  this.bogusReason = null;

  if (typeof packet === "undefined") {
    return;
  }

  this.header = packet.header;
  this.question = packet.question[0];

  var i;
  for (i = 0; i < packet.additional.length; i++) {
    if (packet.additional[i].type === consts.NAME_TO_QTYPE.OPT) {
      this.optRecord = packet.additional[i];
      break;
    }
  }

  var answerRRSets = this.getRRSets(packet.answer);
  var authorityRRSets = this.getRRSets(packet.authority);
  var additionalRRSets = this.getRRSets(packet.additional);

  for (i = 0; i < answerRRSets.length; i++) {
    this.addRRSet(answerRRSets[i], "answer");
  }
  for (i = 0; i < authorityRRSets.length; i++) {
    this.addRRSet(authorityRRSets[i], "authority");
  }
  for (i = 0; i < additionalRRSets.length; i++) {
    this.addRRSet(additionalRRSets[i], "additional");
  }

};

SMessage.prototype.getId = function () {
  return this.header.id || null;
};

SMessage.prototype.setQuestion = function (question) {
  this.question = question;
};

SMessage.prototype.getRRSets = function (section) {
  var sets = [];
  var names = [];

  if(section.length === 0) return [];

  for (var i = 0; i < section.length; i++) {

    var newset = true;

    if (names.indexOf(section[i].name) !== -1) {

      for (var j = sets.length - 1; j >= 0; j--) {

        if (sets[j].getType() == utils.getRRSetType(section[i]) && sets[j].getDClass() == section[i].class && sets[j].getName().toString() == section[i].name) {
          sets[j].addRR(section[i]);
          newset = false;
          break;
        }

      }

    }

    if (newset) {
      var set = new SRRSet();
      set.addRR(section[i]);
      names.push(section[i].name);
      sets.push(set);
    }
  }

  return sets;
};

SMessage.prototype.addRRSet = function (rrset, section) {
  if (rrset.getType() == consts.NAME_TO_QTYPE.OPT) {
    this.optRecord = rrset.first();
    return;
  }

  switch (section) {
    case "answer":
      this.sections.answer = this.sections.answer.concat(rrset);
      break;
    case "authority":
      this.sections.authority = this.sections.authority.concat(rrset);
      break;
    case "additional":
      this.sections.additional = this.sections.additional.concat(rrset);
      break;
    default:
      throw "Invalid Section";
  }
};

SMessage.prototype.getSectionRRsets = function (section, qtype) {
  var rrs = [];
  switch (section) {
    case "answer":
      rrs = this.sections.answer;
      break;
    case "authority":
      rrs = this.sections.authority;
      break;
    case "additional":
      rrs = this.sections.additional;
      break;
    default:
      throw "Invalid Section";
  }

  var result = [];
  for (var i = 0; i < rrs.length; i++) {
    if (typeof qtype !== "undefined" && rrs[i].getType() == qtype) {
      result.push(rrs[i]);
      continue;
    }
    if (typeof qtype === "undefined") {
      result.push(rrs[i]);
    }
  }
  return result;
};

SMessage.prototype.getCount = function (section) {
  if (section == "question") {
    return 1;
  }

  var sectionList = this.getSectionRRsets(section);
  var count = 0;
  for (var i = 0; i < sectionList.length; i++) {
    count += sectionList[i].size();
  }
  return count;
};

SMessage.prototype.getQuestion = function () {
  return this.question;
};

SMessage.prototype.getRcode = function () {
  if (this.optRecord != null) {
    return this.optRecord.rcode;
  }
  return this.header.rcode;
};

SMessage.prototype.getHeader = function () {
  return this.header;
};

SMessage.prototype.findRRset = function (name, type, dclass, section) {

  var sectionSets = this.getSectionRRsets(section);
  for (var i = 0; i < sectionSets.length; i++) {
    if (sectionSets[i].getName().toString() == name.toString() && sectionSets[i].getType() == type && sectionSets[i].getDClass() == dclass) {
      return sectionSets[i];
    }
  }
  return null;
};

SMessage.prototype.findAnswerRRset = function (name, type, dclass) {
  return this.findRRset(name, type, dclass, "answer");
};

SMessage.prototype.setBogus = function (reason) {
  this.securityStatus = SECURITY_STATUS.BOGUS;
  this.bogusReason = reason;
};

exports.SMessage = SMessage;