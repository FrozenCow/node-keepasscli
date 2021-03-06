var fs = require('fs'),
	constants = require('constants'),
	Struct = require('./struct.js').Struct,
	crypto = require('./crypto.js').Crypto,
	sax = require('sax'),
	salsa20 = require('./salsa20').salsa20,
	JXG = require('./jsxcompressor').JXG;

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

function BufferToBytes(b) {
	return Array.prototype.slice.call(b, 0);
}

function UTF8ToBytes(s) {
	var bytes = [];
	for(var i=0;i<s.length;i++) {
		bytes.push(s.charCodeAt(i));
	}
	return bytes;
}

function BytesToUTF8(bytes) {
	var s = '';
	for(var i=0;i<bytes.length;i++) {
		s += String.fromCharCode(bytes[i]);
	}
	return s;
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
	return crypto.SHA256(UTF8ToBytes(password), {asBytes: true});
}

exports.readDatabaseFromFile = function(userKeys, filePath, result, error) {
	var fd = fs.openSync(filePath, 'r');
	var fileSize = fs.statSync(filePath).size;
	var buffer = new Buffer(fileSize);
	if (fs.readSync(fd, buffer, 0, fileSize) < fileSize) {
		throw new KeePassError("Could not read all bytes of file!");
	}
	var bytes = BufferToBytes(buffer);
	return exports.readDatabaseFromBytes(userKeys, bytes, result, error);
};

exports.readDatabaseFromBytes = function(userKeys, bytes, result, error) {
	var filePosition = 0;
	function readStruct(fmt) {
		var l = Struct.CalcLength(fmt);
		var r = Struct.Unpack(fmt, bytes, filePosition);
		filePosition += l;
		return r;
	}
	function readBytes(l) {
		var r = bytes.slice(filePosition, filePosition+l);
		filePosition += l;
		return r;
	}
	
	var header = (function readDatabaseHeader() {
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
				1: function Comment(b) { header.comment = BytesToUTF8(b); },
				2: function CipherID(b) { header.dataCipher = b; },
				3: function CompressionFlags(b) { header.compression = Struct.Unpack('<I', b)[0]; },
				4: function MasterSeed(b) { header.masterSeed = b; },
				5: function TransformSeed(b) { header.transformSeed = b; },
				6: function TransformRounds(b) { header.transformRounds = Struct.Unpack('<L', b)[0]; },
				7: function EncryptionIV(b) { header.encryptionIV = b; },
				8: function ProtectedStreamKey(b) { header.protectedStreamKey = b; },
				9: function StreamStartBytes(b) { header.streamStartBytes = b; },
				10: function RandomStreamID(b) { header.randomStreamID = Struct.Unpack('<I', b)[0]; }
			}[fieldID])(fieldData) || false;
		}
		return header;
	})();
	
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
	var content = (function ReadDecryptAndCheck(decrypter) {
		var bcrypted = readBytes(bytes.length - filePosition);
		var bdecrypted = decrypter(bcrypted);
		
		startBytes = bdecrypted.slice(0, 32);
		
		// Check the first 32 bytes (= startBytes), which should match the unencrypted 32 bytes that was stored in the header (= header.streamStartBytes).
		for (var i=0;i<startBytes.length;i++) {
			if (startBytes[i] !== header.streamStartBytes[i]) {
				throw new KeePassError('Could not decrypt file');
			}
		}
		
		return bdecrypted.slice(32);
	})(decrypter);
	
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
		0: function Uncompressed(input) { return BytesToUTF8(input); },
		1: function Gzip(input) { return new JXG.Util.Unzip(input).unzip()[0][0]; }
	}[header.compression])(content);
	
	// Random bytes generator for in-memory protection. Protected strings are xor-ed with random bytes from this generator.
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
		2: salsa20
	}[header.randomStreamID])(crypto.SHA256(header.protectedStreamKey, {asBytes: true}));
	
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
							var cryptedBytesLength = JXG.Util.Base64.decode(value()).length;
							var randomBytes = randomStream(cryptedBytesLength);
							e.xml.parent[key] = function() {
								var bytes = UTF8ToBytes(JXG.Util.Base64.decode(value()));
								for (var i=0;i<bytes.length; i++) {
									bytes[i] = bytes[i] ^ randomBytes[i];
								}
								return BytesToUTF8(bytes);
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