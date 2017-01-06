var BufferCursor = require('buffercursor'),
    consts = require('native-dns-packet').consts,
    conv = require('binstring'),
    dnsname = require('./name'),
    NDP = require('native-dns-packet'),
    SECURITY_STATUS = require('./srrset').SECURITY_STATUS,
    jsrsasign = require('jsrsasign'),
    BigInteger = require("jsbn").BigInteger;

// TODO: Register GOST curve with JSRSASign ECParameterDB

var ASN1_SEQ = 0x30;
var ASN1_INT = 0x2;
var DSA_LEN = 20;
var DEFAULT_BUFF_SIZE = 4096;
var LABEL_POINTER = 0x0C;

var UnsupportedAlgorithmException = exports.UnsupportedAlgorithmException = function (message) {
  this.name = 'UnsupportedAlgorithmException';
  this.message = message || 'Unknown Algorithm';
  this.stack = (new Error()).stack;
};
UnsupportedAlgorithmException.prototype = Object.create(Error.prototype);
UnsupportedAlgorithmException.prototype.constructor = UnsupportedAlgorithmException;

var isBufferEqual = exports.isBufferEqual = function (a, b) {
  var hexa = conv(a.buffer, {in: 'buffer', out: 'hex'});
  var hexb = conv(b.buffer, {in: 'buffer', out: 'hex'});
  return hexa == hexb;
};

var byteArrayCompare = exports.byteArrayCompare = function (b1, b2) {
  if (b1.length != b2.length)
    return b1.length - b2.length;

  for(var i = 0; i < b1.length; i++) {
    if(b1[i] != b2[i]) {
      return (b1[i] & 0xFF) - (b2[i] & 0xFF);
    }
  }

  return 0;
};

var compareRecords = function (a, b) {
  if (a === b) return 0;

  var n;
  n = a.name.localeCompare(b.name);
  if (n !== 0) {
    return n;
  }

  n = a.class - b.class;
  if (n !== 0) {
    return n;
  }

  n = a.type - b.type;
  if (n !== 0) {
    return n;
  }

  var rdata1 = new BufferCursor(new Buffer(4096));
  var rdata2 = new BufferCursor(new Buffer(4096));
  getRDataBuffer(rdata1, a);
  getRDataBuffer(rdata2, b);
  var rdata1Len = rdata1.tell(), rdata2Len = rdata2.tell();
  rdata1.seek(0);
  rdata2.seek(0);
  rdata1 = rdata1.slice(rdata1Len);
  rdata2 = rdata2.slice(rdata2Len);
  for (var i = 0; i < rdata1.length && i < rdata2.length; i++) {
    n = (rdata1.buffer[i] & 0xFF) - (rdata2.buffer[i] & 0xFF);
    if (n !== 0) {
      return n;
    }
  }

  return (rdata1.length - rdata2.length);
};

var getRDataBuffer = function (buff, val, canonical) {
  var label_index = {};
  var rdata = {};

  switch (val.type) {
    case consts.NAME_TO_QTYPE.A:
    case consts.NAME_TO_QTYPE.AAAA:
      NDP.writeIp(buff, val, {}, {});
      break;

    case consts.NAME_TO_QTYPE.NS:
    case consts.NAME_TO_QTYPE.PTR:
    case consts.NAME_TO_QTYPE.CNAME:
      NDP.writeCname(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.TXT:
    case consts.NAME_TO_QTYPE.SPF:
      NDP.writeTxt(buff, val);
      break;

    case consts.NAME_TO_QTYPE.MX:
      NDP.writeMx(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.SRV:
      NDP.writeSrv(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.SOA:
      NDP.writeSoa(buff, val, label_index, canonical);
      break;

    case consts.NAME_TO_QTYPE.NAPTR:
      NDP.writeNaptr(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.TLSA:
      NDP.writeTlsa(buff, val);
      break;

    case consts.NAME_TO_QTYPE.RRSIG:
      NDP.writeRrsig(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.DS:
      NDP.writeDs(buff, val);
      break;

    case consts.NAME_TO_QTYPE.DNSKEY:
      NDP.writeDnskey(buff, val);
      break;

    case consts.NAME_TO_QTYPE.NSEC3:
      NDP.writeNsec3(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.NSEC3PARAM:
      NDP.writeNsec3Param(buff, val, label_index);
      break;

    case consts.NAME_TO_QTYPE.NSEC:
      NDP.writeNsec(buff, val, label_index);
      break;

    default:
      throw "Unknown Record Type";
  }

  var size = buff.tell();
  buff.seek(0);

  var retBuff = buff.slice(size);
  return retBuff.toByteArray();
};

var matches = function (rrsig, dnskey) {
  var algMatch = dnskey.algorithm == rrsig.algorithm;
  var footprintMatch = getDnskeyFootprint(dnskey) == rrsig.keytag;
  var nameMatch = dnskey.name == rrsig.signerName;
  return algMatch && footprintMatch && nameMatch;
};

var namePack = exports.namePack = function (str, buff, index) {
  var offset, dot, part;

  if (str == ".") {
    buff.writeUInt8(0);
    return;
  }

  while (str) {
    if (index[str]) {
      offset = (NDP.LABEL_POINTER << 8) + index[str];
      buff.writeUInt16BE(offset);
      break;
    } else {
      index[str] = buff.tell();
      dot = str.indexOf('.');
      if (dot > -1) {
        part = str.slice(0, dot);
        str = str.slice(dot + 1);
      } else {
        part = str;
        str = undefined;
      }
      buff.writeUInt8(part.length);
      buff.write(part, part.length, 'ascii');
    }
  }

  if (!str) {
    buff.writeUInt8(0);
  }
};

var readBigInteger = function (buff, len) {
  var content;
  if (typeof len !== 'undefined') {
    content = buff.slice(len);
  } else {
    content = buff.slice();
  }
  return new BigInteger(1, content.toByteArray());
};

var readBigIntegerLittleEndian = function (buff, start, len) {
  var content;
  if (typeof len !== 'undefined') {
    content = buff.slice(start, start + len);
  } else {
    content = buff.slice(start);
  }
  return jsrsasign.parseBigInt(1, conv(content, {in: 'buffer', out: 'bytes'}).reverse());
};

var toPublicKey = exports.toPublicKey = function (record) {
  switch (record.algorithm) {
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSAMD5:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA1:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA1NSEC3SHA1:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA256:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA512:
      return toRSAPublicKey(record);

    case consts.DNSSEC_ALGO_NAME_TO_NUM.DSA:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.DSANSEC3SHA1:
      return toDSAPublicKey(record);

    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECCGOST:
      throw "ECC_GOST DNSKEY Not Yet Supported";
    //return toECGOSTPublicKey(record);

    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP256SHA256:
      return toECDSAPublicKey(record, 256);

    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP384SHA384:
      return toECDSAPublicKey(record, 384);
  }
};

var toRSAPublicKey = function (record) {

  //var buff = new Buffer(record.publicKey.length);
  //buff.copy(record.publicKey);
  var startpos = record.publicKey.tell();
  var buff = record.publicKey;

  var pos = 1;
  var exponentLength = buff.readUInt8();
  if (exponentLength === 0) {
    exponentLength = buff.readUInt16BE();
    pos += 2;
  }
  var exponent = conv(buff.slice(exponentLength), {in: 'buffer', out: 'hex'});
  var modulus = conv(buff.slice(), {in: 'buffer', out: 'hex'});

  record.publicKey.seek(startpos);
  return {
    type: 'RSA',
    key: jsrsasign.KEYUTIL.getKey({n: modulus, e: exponent})
  };
};

var toDSAPublicKey = function (record) {

  var buff = conv(record.publicKey, {in: 'binary', out: 'buffer'});
  var t = buff.readUInt8();
  if (t > 8) {
    throw "Malformed DSA Key";
  }

  var q, p, g, y, pos;
  pos = 1;
  q = readBigInteger(buff, pos, 20);
  pos += 20;

  var numLen = 64 + t * 8;
  p = readBigInteger(buff, pos, numLen);
  pos += numLen;
  g = readBigInteger(buff, pos, numLen);
  pos += numLen;
  y = readBigInteger(buff, pos, numLen);
  pos += numLen;

  return {
    type: 'DSA',
    key: jsrsasign.KEYUTIL.getKey({p: p, q: q, g: g, y: y})
  };
};

var toECGOSTPublicKey = function (record) {
  var buff, pos, x, y;
  buff = conv(record.publicKey, {in: 'binary', out: 'buffer'});
  x = readBigIntegerLittleEndian(buff, pos, 32);
  y = readBigIntegerLittleEndian(buff, pos + 32, 32);

  // TODO: Not completed as jsrsasign ECParameterDB does not contain GOST (yet)
};

var toECDSAPublicKey = function (record, type) {
  var xy, keysize, curve;
  var ecKey = jsrsasign.ECDSA();

  switch (type) {
    case 256:
      curve = 'secp256r1';
      keysize = 32;
      break;
    case 384:
      curve = 'secp384r1';
      keysize = 48;
      break;
  }

  xy = "04";
  xy += conv(record.publicKey.slice(0, keysize), {in: 'buffer', out: 'hex'});
  xy += conv(record.publicKey.slice(keysize, keysize), {in: 'buffer', out: 'hex'});

  return {
    type: 'EC',
    key: jsrsasign.KEYUTIL.getKey({xy: xy, curve: curve})
  };

};

var dsaSignatureFromDNS = function(sig) {
  throw "DSA Signature Not Yet Supported";
};

var ecdsaSignatureFromDNS = function (sig, type) {

  var curvelength;
  switch (type) {
    case 256:
      curvelength = 32;
      break;
    case 384:
      curvelength = 48;
      break;
  }

  if (sig.length != curvelength * 2) {
    throw "Signature Length Verification Failed";
  }

  var sigbuff = conv(sig, {in: 'bytes', out: 'buffer'});
  var out = new Buffer();
  var pos = 0;

  var r = sigbuff.splice(0, curvelength);
  var rlen = curvelength;
  if (r[0] < 0) {
    rlen++;
  }

  var s = sigbuff.splice(curvelength, curvelength);
  var slen = curvelength;
  if (s[0] < 0) {
    slen++;
  }

  out.writeUInt8(ASN1_SEQ);
  pos++;
  out.writeUInt8(rlen + slen + 4);
  pos++;

  out.writeUInt8(ASN1_INT);
  pos++;
  out.writeUInt8(rlen);
  pos++;
  if (rlen > curvelength) {
    out.writeUInt8(0);
    pos++;
  }
  out.copy(r);
  pos += r.length;

  out.writeUInt8(ASN1_INT);
  pos++;
  out.writeUInt8(slen);
  pos++;
  if (slen > curvelength) {
    out.writeUInt8(0);
    pos++;
  }
  out.copy(s);
  pos += s.length;

  var outBuff = out.splice(0, pos);
  return conv(outBuff, {in: 'buffer', out: 'bytes'});
};

var algString = function (alg) {
  switch (alg) {
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSAMD5:
      return "MD5withRSA";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.DSA:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.DSANSEC3SHA1:
      return "SHA1withDSA";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA1:
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA1NSEC3SHA1:
      return "SHA1withRSA";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA256:
      return "SHA256withRSA";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.RSASHA512:
      return "SHA512withRSA";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECCGOST:
      return "GOST3411withECGOST3410";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP256SHA256:
      return "SHA256withECDSA";
    case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP384SHA384:
      return "SHA384withECDSA";
    default:
      throw new UnsupportedAlgorithmException(alg);
  }
};

var verify = function (pubkey, alg, data, sig) {
  var signature;

  if (pubkey.type == 'DSA') {
    signature = dsaSignatureFromDNS(sig);
  } else if (pubkey.type == 'EC') {
    switch (alg) {
      case consts.DNSSEC_ALGO_NAME_TO_NUM.ECCGOST:
        throw "ECC_GOST Not Supported Yet";
        //signature = ECGOSTSignaturefromDNS(sig);
        //break;

      case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP256SHA256:
        signature = ecdsaSignatureFromDNS(sig, 256);
        break;

      case consts.DNSSEC_ALGO_NAME_TO_NUM.ECDSAP384SHA384:
        signature = ecdsaSignatureFromDNS(sig, 384);
        break;
    }
  }

  var s = new jsrsasign.Signature({alg: algString(alg), "prov": "cryptojs/jsrsa"});
  s.init(pubkey.key);
  s.updateHex(conv(data, {in: 'bytes', out: 'hex'}));
  if (!s.verify(conv(sig, {in: 'bytes', out: 'hex'}))) {
    throw "Signature Invalid";
  }

};

/***************************
 * EXPORTED FUNCTIONALITY
 ***************************/
var arrayContains = exports.arrayContains = function (value, array) {
  for (var i = 0; i < array.length; i++) {

    if (typeof array[i] === "object" && typeof value === "object") {
      if (isObjectEquivalent(array[i], value)) return true;
    } else if (array[i] == value) {
      return true;
    }
  }
  return false;
};

var isObjectEquivalent = exports.isObjectEquivalent = function (a, b) {
  // Create arrays of property names
  var aProps = Object.getOwnPropertyNames(a);
  var bProps = Object.getOwnPropertyNames(b);

  // If number of properties is different,
  // objects are not equivalent
  if (aProps.length != bProps.length) {
    return false;
  }

  for (var i = 0; i < aProps.length; i++) {
    var propName = aProps[i];

    // If values of same property are not equal,
    // objects are not equivalent
    if (a[propName] !== b[propName]) {
      return false;
    }
  }

  // If we made it this far, objects
  // are considered equivalent
  return true;
};

var nameRelativize = exports.nameRelativize = function (name, origin) {
  if (typeof origin === "undefined" || origin == null || !name.endsWith(origin)) {
    return name;
  }

  return name.replace(origin, "");
};

var copyByteArray = exports.copyByteArray = function (src, srcPos, dst, dstPos, len) {

  if (dst.length < (dstPos + len))
    throw "Destination ByteArray too small";

  for (var i = 0; i < len; i++) {
    dst[dstPos] = src[srcPos];
    dstPos++;
    srcPos++;
  }
};

var getDnskeyFootprint = exports.getDnskeyFootprint = function (record) {
  if (record.type !== consts.NAME_TO_QTYPE.DNSKEY) {
    throw "Record Type DNSKey Required";
  }

  var foot = 0;
  var size = 4 + record.publicKey.length;
  var buff = new BufferCursor(new Buffer(size));
  buff.writeUInt16BE(record.flags);
  buff.writeUInt8(record.protocol);
  buff.writeUInt8(record.algorithm);
  for (var j = 0; j < record.publicKey.length; j++) {
    buff.writeUInt8(record.publicKey.buffer[j]);
  }

  var d1, d2;

  if (record.algorithm === consts.DNSSEC_ALGO_NAME_TO_NUM.RSAMD5) {
    d1 = buff.buffer[size - 3] & 0xFF;
    d2 = buff.buffer[size - 2] & 0xFF;
    foot = (d1 << 8) + d2;
  } else {
    var i;
    for (i = 0; i < size - 1; i += 2) {
      d1 = buff.buffer[i] & 0xFF;
      d2 = buff.buffer[i + 1] & 0xFF;
      foot += ((d1 << 8) + d2);
    }
    if (i < size) {
      d1 = buff.buffer[i] & 0xFF;
      foot += (d1 << 8);
    }
    foot += ((foot >> 16) & 0xFFFF);
  }
  return (foot & 0xFFFF);
};

/* Digest Utilities */
var generateDSDigest = exports.generateDSDigest = function (key, digestid) {
  var digest;
  if (typeof digestid === "string")
    digestid = parseInt(digestid);

  switch (digestid) {
    case consts.DIGEST_TO_NUM.SHA1:
      digest = new jsrsasign.MessageDigest({alg: "sha1"});
      break;
    case consts.DIGEST_TO_NUM.SHA256:
      digest = new jsrsasign.MessageDigest({alg: "sha256"});
      break;
    case consts.DIGEST_TO_NUM.GOST3411:
      throw "GOST Not Yet Supported";
    case consts.DIGEST_TO_NUM.SHA384:
      digest = new jsrsasign.MessageDigest({alg: "sha384"});
      break;
    default:
      throw "Unknown DS Digest Type: " + digestid;
  }

  // Convert Name to Wire Format & Add to Digest
  digest.updateHex(conv(key.nameRaw, {in: 'bytes', out: 'hex'}));

  // Convert DNSKEY RDATA to Wire Format & Add to Digest
  var buff = new BufferCursor(new Buffer(4 + key.publicKey.length));
  buff.writeUInt16BE(key.flags);
  buff.writeUInt8(key.protocol);
  buff.writeUInt8(key.algorithm);
  for (var j = 0; j < key.publicKey.length; j++) {
    buff.writeUInt8(key.publicKey.buffer[j]);
  }

  digest.updateHex(conv(buff.buffer, {in: 'buffer', out: 'hex'}));
  return digest.digest();

};

var digestSig = function (buff, rrsig) {
  buff.writeUInt16BE(rrsig.typeCovered);
  buff.writeUInt8(rrsig.algorithm);
  buff.writeUInt8(rrsig.labels);
  buff.writeUInt32BE(rrsig.originalTtl);
  buff.writeUInt32BE(rrsig.signatureExpiration.getTime() / 1000);
  buff.writeUInt32BE(rrsig.signatureInception.getTime() / 1000);
  buff.writeUInt16BE(rrsig.keytag);
  namePack(rrsig.signerName, buff, {});
  return buff;
};

var reverse_map = exports.reverse_map = function (src) {
  var dst = {},
      k;

  for (k in src) {
    if (src.hasOwnProperty(k)) {
      dst[src[k]] = k;
    }
  }
  return dst;
};

var digestRRset = exports.digestRRset = function (rrsig, rrset) {
  var buff = new BufferCursor(new Buffer(4096));
  digestSig(buff, rrsig);

  var size = rrset.rrs().length;
  var name = rrset.getName();
  var wild = null;
  var sigLabels = rrsig.labels + 1;

  if (name.labels() > sigLabels) {
    wild = name.wild(name.labels() - sigLabels);
  }


  var records = rrset.rrs().slice();
  records.sort(compareRecords);

  var header = new BufferCursor(new Buffer(256));

  namePack((wild !== null ? wild.toString().toLowerCase() : name.toString().toLowerCase()), header, {});
  header.writeUInt16BE(rrset.getType());
  header.writeUInt16BE(rrset.getDClass());
  header.writeUInt32BE(rrsig.originalTtl);

  var headerLen = header.tell();
  header.seek(0);
  var headerSlice = header.slice(headerLen);
  for (var i = 0; i < records.length; i++) {
    buff.copy(headerSlice);
    var lengthPosition = buff.tell();
    buff.writeUInt16BE(0x0000);

    var recordBuff = new BufferCursor(new Buffer(1024));
    getRDataBuffer(recordBuff, records[i], true);
    var rdataLen = recordBuff.tell();
    recordBuff.seek(0);
    buff.copy(recordBuff.slice(rdataLen));
    var rrlength = buff.tell() - lengthPosition - 2;
    var oldPos = buff.tell();
    buff.seek(lengthPosition);
    buff.writeUInt16BE(rrlength);
    buff.seek(oldPos);
  }
  var fullLen = buff.tell();
  buff.seek(0);
  return buff.slice(fullLen).toByteArray();
};

var getRRSetType = exports.getRRSetType = function (record) {
  if (record.type === consts.NAME_TO_QTYPE.RRSIG) {
    return record.typeCovered;
  }
  return record.type;
};

var verifyRRset = exports.verifyRRset = function (rrset, rrsig, dnskey) {
  if (!matches(rrsig, dnskey)) {
    throw "Key Mismatch";
  }

  var now = new Date();
  if (rrsig.signatureExpiration < now) {
    throw "Signature Expired";
  }
  if (rrsig.signatureInception > now) {
    throw "Signature Not Yet Valid";
  }

  verify(toPublicKey(dnskey), rrsig.algorithm, digestRRset(rrsig, rrset), conv(rrsig.signature.buffer, {
    in: 'buffer',
    out: 'bytes'
  }));
};

var verifyRRsetAgainstDnskey = exports.verifyRRsetAgainstDnskey = function (rrset, dnskey) {
  var sigs = rrset.sigs();
  if (sigs.length === 0) {
    console.log("RRset failed to verify due to lack of signatures");
    return SECURITY_STATUS.BOGUS;
  }

  for (var i = 0; i < sigs.length; i++) {
    if (sigs[i].keytag !== getDnskeyFootprint(dnskey)) continue;
    try {
      verifyRRset(rrset, sigs[i], dnskey);
      return SECURITY_STATUS.SECURE;
    } catch (err) {
      console.log("Failed to Validate RRSet: " + rrset.getName().toString() + " -> " + err);
    }
  }

  console.log("RRset failed to verify: all signatures were BOGUS");
  return SECURITY_STATUS.BOGUS;
};

var parseBindFormat = exports.parseBindFormat = function (bindData) {

  // TODO: We currently only support DNSKEY and DS Records as that's our need

  var zone = {
    records: []
  };

  var lines = bindData.split('\n');
  for (var i = 0; i < lines.length; i++) {
    var data = lines[i].split(new RegExp("\\s+"));

    var typeMatch = lines[i].match(new RegExp("IN\\s+([a-z]+)\\s+", "i"));
    var type = typeMatch[1];

    var record = {
      name: data[0],
      type: consts.NAME_TO_QTYPE[type],
      dclass: consts.NAME_TO_QCLASS.IN
    };

    if (record.type === consts.NAME_TO_QTYPE.DNSKEY) {
      record.ttl = data[1];
      record.flags = data[4];
      record.protocol = data[5];
      record.algorithm = data[6];
      record.publicKey = atob(data[7].replace('(', '').replace(')', '').replace(';', ''));
    }

    if (record.type === consts.NAME_TO_QTYPE.DS) {
      record.keytag = data[3];
      record.algorithm = data[4];
      record.digestType = data[5];
      record.digest = data[6];
    }

    zone.records.push(record);
  }
  return zone;
};

var recordComparator = exports.recordComparator = function (record1, record2) {

  if (record1.name != record2.name) {
    if (record1.name < record2.name) {
      return -1;
    } else {
      return 1;
    }
  }

  var dclassDiff = record1.dclass - record2.dclass;
  if (dclassDiff !== 0) return dclassDiff;

  var typeDiff = record1.type - record2.type;
  if (typeDiff !== 0) return typeDiff;

  var record1Rdata = getRDataBuffer(record1);
  var record2Rdata = getRDataBuffer(record2);
  for (var i = 0; i < record1Rdata.length && i < record2Rdata; i++) {
    var n = (record1Rdata[i] & 0xFF) - (record2Rdata[i] & 0xFF);
    if (n !== 0) return n;
  }

  return (record1Rdata.length - record2Rdata.length);
};

/* Name Handlers */
var strictSubdomain = exports.strictSubdomain = function (domain1, domain2) {
  domain1 = dnsname.newNameFromString(domain1.toString());
  domain2 = dnsname.newNameFromString(domain2.toString());

  if (domain1.labels() <= domain2.labels()) {
    return false;
  }

  return dnsname.newNameRemoveLabels(domain1, domain1.labels() - domain2.labels()).equals(domain2);
};

var compareNames = exports.compareNames = function (name1, name2) {
  if (name1 == name2) return 0;
  if (name1 < name2) return -1;
  if (name1 > name2) return 1;
  throw "Name comparison failed";
};

var getLabels = exports.getLabels = function (name) {
  if (name == ".") return 1;
  var len = name.split('.').length;
  if (len == 1 && name === "") return 0;
  return len;
};

var removeNameLabels = exports.removeNameLabels = function (name, labels) {
  if (labels < 1) return name;
  if (name == "." && labels == 1) return "";
  var ret = name.split('.').slice(labels).join('.');
  if (ret === "") {
    return ".";
  }
  return ret;
};

var getWildName = exports.getWildName = function (name, level) {
  if (level < 1) {
    return name;
  }
  var nameRemoved = name.split('.').splice(1);
  nameRemoved.insert(0, '*');
  return nameRemoved.join('.');
};

var FindKeyState = exports.FindKeyState = function () {
  this.dsRRset = null;
  this.keyEntry = null;
  this.signerName = null;
  this.qclass = null;
  this.emptyDSName = null;
  this.currentDSKeyName = null;
};

var JustifiedSecStatus = exports.JustifiedSecStatus = function (status, reason) {
  this.status = status;
  this.reason = reason;
};

var NsecProvesNodataResponse = exports.NsecProvesNodataResponse = function () {
  this.result = false;
  this.wc = undefined;
};