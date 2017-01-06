var DNSSEC = require('./lib/main'),
    consts = require('native-dns-packet').consts;

module.exports = {
  SECURITY_STATUS: DNSSEC.SECURITY_STATUS,
  DNSSECResolver: DNSSEC.DNSSECResolver,
  DNSSECQuery: DNSSEC.DNSSECQuery,
  consts: consts
};