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
		2: function Salsa20(key) {
				var iv = [ 0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A ];
				var sigma = [ 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 ];
				var x = clearArray(new Array(16), 0);
				var state = clearArray(new Array(16), 0);
				var output = clearArray(new Array(64), 0);
				setupKey(state);
				setupIV(state);
				
				var outputPos = 64;
				
				function clearArray(b, n) {
					for(var i=0;i<b.length;i++) { b[i]=n; }
					return b;
				}
				function unsigned(a) {
					return ((a | 1) >>> 1) * 2 + (a & 1);
				}
				function lshift(a, b) {
					return unsigned(a << b);
				}
				function rshift(a, b) {
					return a >>> Math.min(32, b);
				}
				function bor(a, b) {
					return unsigned(a | b);
				}
				function bxor(a, b) {
					return unsigned(a ^ b);
				}
				function U8To32Little(b, offset) {
					return bor(bor(bor(b[offset], lshift(b[offset+1], 8)), lshift(b[offset+2], 16)), lshift(b[offset+3], 24));
				}
				function setupKey(state) {
					state[1] = U8To32Little(key, 0);
					state[2] = U8To32Little(key, 4);
					state[3] = U8To32Little(key, 8);
					state[4] = U8To32Little(key, 12);
					state[11] = U8To32Little(key, 16);
					state[12] = U8To32Little(key, 20);
					state[13] = U8To32Little(key, 24);
					state[14] = U8To32Little(key, 28);
					state[0] = sigma[0];
					state[5] = sigma[1];
					state[10] = sigma[2];
					state[15] = sigma[3];
				}
				function setupIV(state) {
					state[6] = U8To32Little(iv, 0);
					state[7] = U8To32Little(iv, 4);
					state[8] = 0;
					state[9] = 0;
				}
				function rotl32(x, b) {
					return bor(lshift(x, b), rshift(x, (32 - b)));
				}
				function add(a, b) {
					return (a + b);
				}
				
				function nextOutput() {
					x = state.slice(0);
					function rot(i, n) {
						x[i] = bxor(x[i], n);
					}
					for(var i = 0; i < 10; ++i) {
						rot( 4, rotl32(add(x[ 0], x[12]),  7));
						rot( 8, rotl32(add(x[ 4], x[ 0]),  9));
						rot(12, rotl32(add(x[ 8], x[ 4]), 13));
						rot( 0, rotl32(add(x[12], x[ 8]), 18));
						rot( 9, rotl32(add(x[ 5], x[ 1]),  7));
						rot(13, rotl32(add(x[ 9], x[ 5]),  9));
						rot( 1, rotl32(add(x[13], x[ 9]), 13));
						rot( 5, rotl32(add(x[ 1], x[13]), 18));
						rot(14, rotl32(add(x[10], x[ 6]),  7));
						rot( 2, rotl32(add(x[14], x[10]),  9));
						rot( 6, rotl32(add(x[ 2], x[14]), 13));
						rot(10, rotl32(add(x[ 6], x[ 2]), 18));
						rot( 3, rotl32(add(x[15], x[11]),  7));
						rot( 7, rotl32(add(x[ 3], x[15]),  9));
						rot(11, rotl32(add(x[ 7], x[ 3]), 13));
						rot(15, rotl32(add(x[11], x[ 7]), 18));
						rot( 1, rotl32(add(x[ 0], x[ 3]),  7));
						rot( 2, rotl32(add(x[ 1], x[ 0]),  9));
						rot( 3, rotl32(add(x[ 2], x[ 1]), 13));
						rot( 0, rotl32(add(x[ 3], x[ 2]), 18));
						rot( 6, rotl32(add(x[ 5], x[ 4]),  7));
						rot( 7, rotl32(add(x[ 6], x[ 5]),  9));
						rot( 4, rotl32(add(x[ 7], x[ 6]), 13));
						rot( 5, rotl32(add(x[ 4], x[ 7]), 18));
						rot(11, rotl32(add(x[10], x[ 9]),  7));
						rot( 8, rotl32(add(x[11], x[10]),  9));
						rot( 9, rotl32(add(x[ 8], x[11]), 13));
						rot(10, rotl32(add(x[ 9], x[ 8]), 18));
						rot(12, rotl32(add(x[15], x[14]),  7));
						rot(13, rotl32(add(x[12], x[15]),  9));
						rot(14, rotl32(add(x[13], x[12]), 13));
						rot(15, rotl32(add(x[14], x[13]), 18));
					}
					for(var i = 0; i < 16; ++i) {
						x[i] += state[i];
					}
					for(var i = 0; i < 16; ++i) {
						output[i << 2] = x[i] & 0xff;
						output[(i << 2) + 1] = rshift(x[i], 8) & 0xff;
						output[(i << 2) + 2] = rshift(x[i], 16) & 0xff;
						output[(i << 2) + 3] = rshift(x[i], 24) & 0xff;
					}
	
					state[8] = add(state[8], 1);
					if(state[8] === 0) {
						state[9] = add(state[9], 1);
					}
				}
				
				return function(byteCount) {
					var bytesRem = byteCount;
					var data = new Array(byteCount);
					var nOffset = 0;
					while (bytesRem > 0) {
						if (outputPos === 64) {
							nextOutput();
							outputPos = 0;
						}
						var nCopy = Math.min(64 - outputPos, bytesRem);
						for(var i=0;i<nCopy;i++){
							data[i+nOffset] = output[i+outputPos];
						}
						outputPos += nCopy;
						bytesRem -= nCopy;
						nOffset += nCopy;
					}
					return data;
				};
			}
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