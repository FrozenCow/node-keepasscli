var fs = require('fs'),
	Buffer = require('buffer').Buffer,
	constants = require('constants'),
	Struct = require('./struct.js').Struct,
	crypto = require('./crypto.js').Crypto,
	sax = require('sax');

Buffer.prototype.toByteArray = function() { return Array.prototype.slice.call(this, 0) }

Buffer.prototype.concat = function(b) {
	var r = new Buffer(this.length + b.length);
	this.copy(r, 0, 0);
	b.copy(r, this.length, 0);
	return r;
}

function toHex(a) {
	if (a instanceof Array) {
		var result = '';
		for (var i = 0; i < a.length; i++) {
			result += toHex(a[i]);
		}
		return result;
	} else if (typeof a === 'number') {
		if (a > 255 || a < 0) { throw new Error('Invalid input, toHex received a non-byte'); }
		return (a < 16 ? '0' : '') + a.toString(16);
	} else {
		throw new Error('Unknown type, not able to convert to hex: ' + typeof a);
	}
}

function toBytes(i, encoding) {
	if (i instanceof Buffer) {
		return Array.prototype.slice.call(i, 0);
	} else if (typeof i === 'string' || i instanceof String) {
		if (!encoding) { throw "Unsupported encoding"; }
		return toBytes(new Buffer(i, encoding));
	} else if (i instanceof Array) {
		return i.slice(0);
	} else {
		console.error(typeof i);
		throw "Unsupported type";
	}
}

function dbg(i) {
	// Disabled debugging.
	//console.log.apply(console, Array.prototype.slice.apply(arguments, [0, arguments.length-1]).concat([toHex(arguments[arguments.length-1])]));
	return arguments[arguments.length-1];
}

function KeePassError(message) {
	this.message = message;
}

exports.userPassword = function(password) {
	return crypto.SHA256(toBytes(password, 'utf8'), {asBytes: true});
}

function xorBytes(a, b) {
	var r = [];
	for(var i=0;i<a.length;i++) {
		r.push(a[i] ^ (b ? b[i] : 0xff));
	}
	return r;
}

exports.decryptPassword = function(db, password) {
	if (!password || !password['@'] || !password['#']) return undefined;
	if (password['@'].Protected !== 'True') {
		return password['#'];
	}
	var encryptedBytes = toBytes(password['#'], 'base64');
	
	var random = new Array(encryptedBytes.length);
	for(var i=0;i<random.length;i++) {
		random[i] = 0;
	}
	random = db.protectedStringDecrypter(random);
	var decryptedBytes = xorBytes(encryptedBytes);
	/*for(var i=0;i<decryptedBytes.length;i++) {
		decryptedBytes[i] = decryptedBytes[i] ^ 0xff;
	}*/
	//console.log(decryptedBytes);
	return new Buffer(decryptedBytes).toString('utf8');
}

exports.readDatabase = function(userKeys, filePath, result, error) {// try {
	var databaseFile = (function openDatabaseFile(filePath) {
		return {
			size: fs.statSync(filePath).size,
			fd: fs.openSync(filePath, 'r')
		};
	})(filePath);

	var header = (function readDatabaseHeader(databaseFile) {
		function readBytes(l) {
			var b = new Buffer(l);
			if (fs.readSync(databaseFile.fd, b, 0, l) < l) {
				throw new KeePassError("Could not read struct");
			}
			return toBytes(b);
		}
		function unpack(fmt, b) {
			return Struct.Unpack(fmt, b);
		}
		function readStruct(fmt) {
			var l = Struct.CalcLength(fmt);
			var b = readBytes(l);
			return unpack(fmt, b);
		}
		
		var sigs = readStruct('<I<I');
		if (sigs[0] !== 0x9AA2D903 ||
			sigs[1] !== 0xB54BFB67) {
			throw new KeePassError("Incorrect format");
		}
		
		var version = readStruct('<I');
		if ((version & 0xFFFF0000) > (0x02010100 & 0xFFFF0000)) {
			throw new KeePassError("Incorrect version");
		}
		
		var header = {};
		while (!readHeaderField()) { }
		
		function readHeaderField() {
			var fieldID = readStruct('<B')[0];
			var fieldSize = readStruct('<H')[0];
			var fieldData = readBytes(fieldSize);
			return ({
				0: function EndOfHeader(b) { return true; },
				1: function Comment(b) { header.comment = new Buffer(b).toString('utf8'); },
				2: function CipherID(b) { header.dataCipher = b; },
				3: function CompressionFlags(b) { header.compression = unpack('<I', b)[0]; },
				4: function MasterSeed(b) { header.masterSeed = b; },
				5: function TransformSeed(b) { header.transformSeed = b; },
				6: function TransformRounds(b) { header.transformRounds = unpack('<L', b)[0]; },
				7: function EncryptionIV(b) { header.encryptionIV = b; },
				8: function ProtectedStreamKey(b) { header.protectedStreamKey = b; },
				9: function StreamStartBytes(b) { header.streamStartBytes = b; },
				10: function RandomStreamID(b) { header.randomStreamID = unpack('<I', b)[0]; }
			}[fieldID])(fieldData) || false;
		}
		return header;
	})(databaseFile);
	
	var randomStream = ({
		0: function Null(key) { return function(data) { return data; } },
		1: function ArcFourVariant(key) {
			/*
			for(uint w = 0; w < uRequestedCount; ++w)
			{
				++m_i;
				m_j += m_pbState[m_i];

				byte t = m_pbState[m_i]; // Swap entries
				m_pbState[m_i] = m_pbState[m_j];
				m_pbState[m_j] = t;

				t = (byte)(m_pbState[m_i] + m_pbState[m_j]);
				pbRet[w] = m_pbState[t];
			}
			*/
			},
		2: require('./salsa20').salsa20
	}[header.randomStreamID])(crypto.SHA256(header.protectedStreamKey, {asBytes: true}));
	
	// Create key with which to decrypt the rest of the file.
	var finalKey = (function fabricateDecryptionKey(userKeys) {
		function transformKey(raw, keyseed, rounds) {
			var key = raw;
		
			var iv = [];
			for (var i = 0; i < 16; i++) { iv.push(0); }
			
			var opt = {mode: new crypto.mode.ECB(crypto.pad.NoPadding), iv: iv, asBytes: true};
			for (var i = 0; i < rounds; i++) {
				key = crypto.AES.encrypt(key, keyseed, opt);
			}
			return crypto.SHA256(key, {asBytes: true});
		}
		
		var concatKeys = [];
		userKeys.forEach(function(userKey) { concatKeys = concatKeys.concat(userKey); });
		var compositeKey = crypto.SHA256(concatKeys, {asBytes: true});
		var transformedMasterKey = transformKey(compositeKey, header.transformSeed, header.transformRounds);
		return crypto.SHA256(header.masterSeed.concat(transformedMasterKey), {asBytes: true});
	})(userKeys);
	
	// Create the decryptor based on the DataCipher-type that is stored in the database.
	var decrypter = ({
		'31c1f2e6bf714350be5805216afc5aff': function AES_CBC_PKCS7(key, iv) {
			var options = {mode: new crypto.mode.CBC(crypto.pad.pkcs7), iv: iv, asBytes: true};
			return function(input) {
				return crypto.AES.decrypt(input, key, options);
			};
		}
	}[toHex(header.dataCipher)])(finalKey, header.encryptionIV);
	
	// Decrypt the rest of the file using the decrypter.
	var content = (function ReadDecryptAndCheck(databaseFile, decrypter) {
		var b = new Buffer(databaseFile.size);
		var size = fs.readSync(databaseFile.fd, b, 0, databaseFile.size);
		var bcrypted = Array.prototype.slice.apply(b, [0, size]);
		var bdecrypted = decrypter(bcrypted);
		
		startBytes = bdecrypted.slice(0, 32);
		
		// Check the first 32 bytes (= startBytes), which should match the unencrypted 32 bytes that was stored in the header (= header.streamStartBytes).
		for (var i=0;i<startBytes.length;i++) {
			if (startBytes[i] !== header.streamStartBytes[i]) {
				throw new KeePassError('Could not decrypt file');
			}
		}
		
		return bdecrypted.slice(32);
	})(databaseFile, decrypter);
	
	// Check every chunk of data with its preceding hash and concat all chunks to one byte array.
	content = (function CheckAndConcatHashedBlocks(content) {
		var contentPosition = 0;
		function unpack(fmt) {
			var l = Struct.CalcLength(fmt);
			var r = Struct.Unpack(fmt, content, contentPosition);
			contentPosition += l;
			return r;
		}
		function readBytes(l) {
			var r = content.slice(contentPosition, contentPosition+l);
			contentPosition += l;
			return r;
		}
		
		var blockIndex = 0;
		var unhashedContent = [];
		while(true) {
			var readBlockIndex = unpack('<I')[0];
			if (blockIndex !== readBlockIndex) {
				throw 'Invalid index, file is broken?';
			}
			blockIndex++;
			var blockHash = readBytes(32);
			var blockSize = unpack('<i')[0];
			
			// End Of File
			if (blockSize === 0) { break; }
			
			var blockBytes = readBytes(blockSize);
			
			var calculatedHash = crypto.SHA256(blockBytes, {asBytes: true});
			for (var i=0;i<32;i++) {
				if (blockHash[i] !== calculatedHash[i]) {
					throw new Error('Invalid hash, file broken?');
				}
			}
			unhashedContent = unhashedContent.concat(blockBytes);
		}
		return unhashedContent;
	})(content);
	
	// Uncompress the resulting bytes if the database is indeed marked (by db.compression) as compressed.
	content = ({
		0: function Uncompressed(input) { return new Buffer(input).toString('utf8'); },
		1: function Gzip(input) { return require('./jsxcompressor').JXG.decompress(new Buffer(input).toString('base64')); }
	}[header.compression])(content);
	
	(function parseXML(result) {
		var parser = sax.parser(true);
		var tagStack = [];
		var root = undefined;
		tagStack.peek = function() { return this[this.length-1]; };
		parser.onerror = function() {
			error('error parsing xml');
		};
		parser.ontext = function(t) {
			var parent = tagStack.peek();
			if (parent) {
				parent.xml._text = t;
			}
		};
		parser.onopentag = function(t) {
			var e = {xml: {name: t.name, attributes: [], children: []}};
			var parent = tagStack.peek();
			if (parent) {
				e.xml.parent = parent;
				parent.xml.children.push(e);
			}
			tagStack.push(e);
		};
		parser.onclosetag = function(t) {
			var e = tagStack.pop();
			
			// Add extra info to make elements workable with js.
			function getall(name) { return function() { return e.xml.children.filter(function(e) { return e.xml.name === name; }); } }
			function getfirst(name) { return function() { return e.xml.children.filter(function(e) { return e.xml.name === name; })[0]; } }
			function gettext(name) { return function() { return e.xml.children.filter(function(e) { return e.xml.name === name; })[0]._text; } }
			switch(e.xml.name) {
				case 'String':
					var isprotected = e.xml.attributes.filter(function(a) { return a.name === 'Protected' && a.value === 'True' }).length > 0;
					var key = e.xml.children.filter(function(e) { return e.xml.name === 'Key' }).map(function(e) { return e.xml._text })[0];
					var value = function() { return e.xml.children.filter(function(e) { return e.xml.name === 'Value' }).map(function(e) { return e.xml._text})[0]; };
					if (key && value()) {
						if (isprotected) {
							var cryptedBytesLength = new Buffer(value(), 'base64').length;
							var randomBytes = randomStream(cryptedBytesLength);
							e.xml.parent[key] = function() {
								var bytes = new Buffer(value(), 'base64');
								for (var i=0;i<bytes.length; i++) {
									bytes[i] = bytes[i] ^ randomBytes[i];
								}
								return bytes.toString('utf8');
							};
						} else {
							e.xml.parent[key] = value;
						}
					}
					break;
				case 'KeePassFile':
					e.root = getfirst('Root');
					e.meta = getfirst('Meta');
					e.header = function() { return header; };
					break;
				case 'Root':
				case 'Group':
					e.uuid = gettext('UUID');
					e.name = gettext('Name');
					e.entries = getall('Entry');
					e.groups = getall('Group');
					break;
			}
			if (tagStack.length === 0) {
				result(e);
			}
		};
		parser.onattribute = function(a) {
			var parent = tagStack.peek();
			if (parent) {
				parent.xml.attributes.push(a);
			}
		};
		parser.write(content);
	})(function(r) {
		result(r);
	});
/*} catch(e) {
	if (e instanceof KeePassError) {
		error(new Error(e.message));
	} else {
		throw e;
	}
}*/}

function arr(o) {
	if (o) {
		if (o instanceof Array) { return o; }
		if (typeof o === 'object') { return [o]; }
	}
	return [];
}


function getentries(database, entry) {
	(function handlegroup(group) {
		arr(group.Entry).forEach(function(e) { entry(e); });
		arr(group.Group).forEach(handlegroup);
	})(database.Root.Group);
}

function handleentries(entries) {
	function getString(e, name) {
		return arr(e.String).filter(function(str) { return str.Key === name; }).map(function(str) { return typeof str.Value === 'string' ? str.Value : undefined; })[0];
	}
	
	function title(t) {
		if (typeof t === 'string') { t = new RegExp(t); }
		return function(e) { return t.test(getString(e, 'Title')); }
	}
	entries.filter(title(/Softwarebakery/)).forEach(function(e) { console.log(getString(e, 'Title'), getString(e, 'UserName')); });
}