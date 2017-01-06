/*jshint -W117 */
'use strict';

var dgram = require('dgram');

var SOCKET_TYPE = {
  NODE: 1,
  CORDOVA: 2,
  CHROME: 3
};

function toArrayBuffer(buffer) {
  var ab = new ArrayBuffer(buffer.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
    view[i] = buffer[i];
  }
  return ab;
}

function toBuffer(ab) {
  var buffer = new Buffer(ab.byteLength);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; ++i) {
    buffer[i] = view[i];
  }
  return buffer;
}

function chromeUdpSendHandler(result) {
  console.log(result);
}

var UdpProviderSocket = function (type, socket) {
  this._type = type;
  this._socket = socket;
};

UdpProviderSocket.prototype.send = function (buff, start, end, port, server) {
  switch (this._type) {
    case SOCKET_TYPE.NODE:
      return this._socket.send(buff, start, end, port, server);

    case SOCKET_TYPE.CORDOVA:

      if (this._socket == 'TBD') {
        var self = this;
        return chrome.sockets.udp.getSockets(function (results) {
          for (var result in results) {
            if (results.hasOwnProperty(result)) {
              self._socket = results[result].socketId;
              break;
            }
          }
          chrome.sockets.udp.send(self._socket, toArrayBuffer(buff.slice(start, end)), server, port, chromeUdpSendHandler);
        });
      }

      return chrome.sockets.udp.send(this._socket, toArrayBuffer(buff.slice(start, end)), server, port, chromeUdpSendHandler);

    case SOCKET_TYPE.CHROME:
      console.log('Chrome WebApp UDP Provider Not Yet Supported');
      break;
  }
};

var createSocket = exports.createSocket = function (type, callback) {

  // Check for dgram presence
  if (dgram.hasOwnProperty('createSocket')) {
    return new UdpProviderSocket(SOCKET_TYPE.NODE, dgram.createSocket(type, callback));
  }

  // Check for CORDOVA Plugin Availability
  if (typeof chrome !== 'undefined') {
    chrome.sockets.udp.create({}, function (socketInfo) {
      var socketId = socketInfo.socketId;
      chrome.sockets.udp.onReceive.addListener(function (receiveInfo) {
        callback(toBuffer(receiveInfo.data));
      });
      chrome.sockets.udp.bind(socketId, "0.0.0.0", 0, function (result) {
        if (result < 0) {
          console.log("Error binding socket.");
        }
      });
    });
    return new UdpProviderSocket(SOCKET_TYPE.CORDOVA, 'TBD');
  }
};