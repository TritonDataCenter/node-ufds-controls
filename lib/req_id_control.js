/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var asn1 = require('asn1');
var assert = require('assert-plus');
var ldap = require('ldapjs');
var util = require('util');

///--- Globals

var Control = ldap.Control;
var BerReader = asn1.BerReader;
var BerWriter = asn1.BerWriter;

// JSSTYLED
var UUID_REGEXP = /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/;


///--- API

function ReqIdControl(opts) {
    if (!opts) {
        opts = {};
    }

    opts.type = ReqIdControl.OID;
    if (opts.value) {
        if (Buffer.isBuffer(opts.value)) {
            this.parse(opts.value);
        } else if (typeof (opts.value) === 'string') {
            assert.uuid(opts.value);
            this._value = opts.value;
        } else {
            throw new TypeError('opts.value must be a Buffer or String');
        }
        opts.value = null;
    }
    Control.call(this, opts);
}
ReqIdControl.OID = '1.3.6.1.4.1.38678.1.1.7';
util.inherits(ReqIdControl, Control);
module.exports = ReqIdControl;

ReqIdControl.prototype.parse = function parse(buffer) {
    assert.ok(buffer);
    var value = buffer.toString('utf8');
    if (UUID_REGEXP.test(value)) {
        this._value = value;
        return true;
    }
    return false;
};

ReqIdControl.prototype._toBer = function _toBer(ber) {
    assert.ok(ber);

    if (!this._value) {
        return;
    }
    ber.writeString(this._value, asn1.Ber.OctetString);
};

ReqIdControl.prototype._json = function _json(obj) {
    obj.controlValue = this.value;
    return obj;
};
