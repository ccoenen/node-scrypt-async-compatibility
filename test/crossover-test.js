var assert = require('assert');

var scryptOld = require('scrypt');

var compatibility = require('../node-scrypt-async-compatibility');

describe('crossover', () => {
	it('goes from scrypt to scrypt-async', () => {
		const password = Buffer.from('hello', 'ASCII');
		const buffer = scryptOld.kdfSync(password, scryptOld.paramsSync(0.1));

		return compatibility.verifyKdf(buffer, password).then(() => {
			assert.ok(true, 'works');
		}, () => {
			assert.fail('should never end up here');
		});
	});

	it('goes from scrypt-async to scrypt', () => {
		const password = Buffer.from('ohai', 'ASCII');

		return compatibility.kdf(password, {logN: 13, r: 8, p: 1}).then((result) => {
			assert(scryptOld.verifyKdfSync(result, password));
		});
	});
});
