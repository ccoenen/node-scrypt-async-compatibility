var assert = require('assert');

var compatibility = require('../node-scrypt-async-compatibility');
var headers = require('./fixtures/headers');

describe('verifyKdf', () => {
	it('resolves for correct key', () => {
		let buffer = Buffer.alloc(96, headers.valid['this is a key'], 'HEX');

		return compatibility.verifyKdf(buffer, Buffer.from('this is a key', 'ASCII')).then(() => {
			assert.ok(true, 'works');
		}, () => {
			assert.fail('should never end up here');
		});
	});

	it('rejects incorrect key.', () => {
		let buffer = Buffer.alloc(96, headers.valid['this is a key'], 'HEX');

		return compatibility.verifyKdf(buffer, Buffer.from('dude where\'s my password?', 'ASCII')).then(() => {
			assert.fail('should never end up here');
		}, () => {
			assert.ok(true, 'works');
		});
	});
});
