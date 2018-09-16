var compatibility = require('../node-scrypt-async-compatibility');

describe('kdf', () => {
	it('creates a header with salt', () => {
		return compatibility.kdf(Buffer.from('test', 'ASCII'), {
			logN: 13,
			r: 8,
			p: 1,
			salt: Buffer.alloc(16)
		});
	});

	it('creates a header without salt', () => {
		return compatibility.kdf(Buffer.from('test', 'ASCII'), {
			logN: 13,
			r: 8,
			p: 1
		});
	});
});
