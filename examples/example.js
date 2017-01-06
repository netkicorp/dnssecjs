var dnssec = require('../lib/main.js'),
    consts = require('native-dns-packet').consts;

var request = new dnssec.DNSSECQuery({
        name: "ietf.org.",
        type: 'A'
    }
);

var resolver = new dnssec.DNSSECResolver(request);
resolver.debug = false;
resolver.loadTrustAnchors(". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5");
resolver.on('complete', function (response) {
    console.log('Completed Resolution with Security Status: ' + response.securityStatus);
    var i, rec;
    for(i=0; i < response.sections.answer.length; i++) {
        rec = response.sections.answer[i];
        console.log("ANSWER[" + i + "]: " + rec.getName().toString() + " (" + consts.qtypeToName(rec.getType()) + "): " + rec.first().address);
    }
    for(i=0; i < response.sections.authority.length; i++) {
        rec = response.sections.authority[i];
        console.log("AUTHORITY[" + i + "]: " + rec.getName().toString() + " (" + consts.qtypeToName(rec.getType()) + ")");
    }
    for(i=0; i < response.sections.additional.length; i++) {
        rec = response.sections.additional[i];
        console.log("ADDITIONAL[" + i + "]: " + rec.getName().toString() + " (" + consts.qtypeToName(rec.getType()) + ")");
    }
    process.exit();
});

resolver.resolve();