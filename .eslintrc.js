module.exports = {
	"env": {
		"node": true,
		"es6": true,
		"mocha": true
	},
	"parserOptions": {
		"ecmaVersion": 6,
	},
	"extends": "eslint:recommended",
	"rules": {
		"indent": [
			"error",
			"tab"
		],
		"linebreak-style": [
			"error",
			"unix"
		],
		"quotes": [
			"error",
			"single"
		],
		"semi": [
			"error",
			"always"
		]
	}
};
