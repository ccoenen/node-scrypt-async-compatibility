var assert = require('assert');

var compatibility = require('../node-scrypt-async-compatibility');
var headers = require('./fixtures/headers');

describe('parseScryptHeader', () => {
	it('throws for wrong header format', () => {
		let buffer = Buffer.alloc(96, 'hello', 'ASCII');
		assert.throws(() => {
			compatibility.parseScryptHeader(buffer);
		});

		buffer = Buffer.alloc(96, 'scrypt', 'ASCII');
		buffer[6] = 0x01;
		assert.throws(() => {
			compatibility.parseScryptHeader(buffer);
		});
	});

	it('throws for wonky checksum', () => {
		const invalid = headers.invalid.checksum;

		let buffer = Buffer.alloc(96, invalid, 'HEX');
		assert.throws(() => {
			compatibility.parseScryptHeader(buffer);
		});
	});
});
