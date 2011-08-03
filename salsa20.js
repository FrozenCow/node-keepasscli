exports.salsa20 = function(key) {
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
};