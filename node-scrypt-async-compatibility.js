'use strict';

/*
 * Compatibility with the format as seen in node-scrypt, written by Barry Steyn.
 * Scrypt by Colin Percival.
 * TARSNAP / scrypt format definition: https://github.com/Tarsnap/scrypt/blob/master/FORMAT
 * https://github.com/barrysteyn/node-scrypt/blob/master/scrypt/scrypt-1.2.0/keyderivation.c#L60-L77 and
 * special thanks to @dchest https://github.com/dchest/scrypt-async-js/issues/44#issuecomment-421709388
 */


var crypto = require('crypto');

var scrypt = require('scrypt-async');

module.exports = {
	sign: function (buffer, key) {
		var hmacKey = key.subarray(32);
		var result = crypto.createHmac('sha256', hmacKey)
			.update(buffer.slice(0, 64))
			.digest();
		return result;
	},

	parseScryptHeader: function (buffer) {
		var b = buffer;

		if (b.toString('ASCII', 0, 6) !== 'scrypt' || b[6] !== 0x00) {
			throw 'this is not scrypt version 0';
		}

		var parsed = {
			logN: b.readUInt8(7),
			r: b.readUInt32BE(8),
			p: b.readUInt32BE(12),
			salt: b.slice(16, 48),
			checksum: b.slice(48, 64),
			signature: b.slice(64, 96)
		};

		var checksumVerification = crypto.createHash('SHA256');
		checksumVerification.update(b.slice(0, 48));
		var digest = checksumVerification.digest().slice(0, 16);
		if (!digest.equals(parsed.checksum)) {
			throw 'something is odd while parsing: checksums do not match';
		}

		return parsed;
	},

	kdf: function (key, options) {
		return new Promise((resolve) => {
			var b = Buffer.alloc(96);

			b.fill('scrypt', 0, 6, 'ASCII');
			b[6] = 0x00;
			b[7] = options.logN;
			b.writeUInt32BE(options.r, 8);
			b.writeUInt32BE(options.p, 12);

			var salt = options.salt || crypto.randomBytes(32);
			salt.copy(b, 16, 0, 32);

			var checksum = crypto.createHash('SHA256');
			checksum.update(b.slice(0, 48));
			checksum.digest().copy(b, 48, 0, 16); // copy bytes 0-15 to buffer

			scrypt(key, salt, {
				logN: options.logN,
				r: options.r,
				p: options.p,
				dkLen: 64,
				encoding: 'binary'
			}, function (cryptedKey) {
				var signature = module.exports.sign(b, cryptedKey);
				signature.copy(b, 64, 0, 32);
				resolve(b);
			});
		});
	},

	verifyKdf: function (storedScryptHeader, keyAttempt) {
		return new Promise(function (resolve, reject) {
			var scryptParams = module.exports.parseScryptHeader(storedScryptHeader);

			// let's see if we can verify it! This means recreating a hash with
			// the same parameters and trying to get the same result.
			module.exports.kdf(keyAttempt, scryptParams).then((candidate) => {
				if (crypto.timingSafeEqual(candidate, storedScryptHeader)) {
					resolve();
				} else {
					reject();
				}
			});
		});
	}
};
