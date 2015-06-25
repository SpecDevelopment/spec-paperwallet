var ninja = { wallets: {} };

ninja.privateKey = {
	isPrivateKey: function (key) {
		return (
					SPEC.ECKey.isWalletImportFormat(key) ||
					SPEC.ECKey.isCompressedWalletImportFormat(key) ||
					SPEC.ECKey.isHexFormat(key) ||
					SPEC.ECKey.isBase64Format(key) ||
					SPEC.ECKey.isMiniFormat(key)
				);
	},
	getECKeyFromAdding: function (privKey1, privKey2) {
		var n = EllipticCurve.getSECCurveByName("secp256k1").getN();
		var ecKey1 = new SPEC.ECKey(privKey1);
		var ecKey2 = new SPEC.ECKey(privKey2);
		// if both keys are the same return null
		if (ecKey1.getSPECHexFormat() == ecKey2.getSPECHexFormat()) return null;
		if (ecKey1 == null || ecKey2 == null) return null;
		var combinedPrivateKey = new SPEC.ECKey(ecKey1.priv.add(ecKey2.priv).mod(n));
		// compressed when both keys are compressed
		if (ecKey1.compressed && ecKey2.compressed) combinedPrivateKey.setCompressed(true);
		return combinedPrivateKey;
	},
	getECKeyFromMultiplying: function (privKey1, privKey2) {
		var n = EllipticCurve.getSECCurveByName("secp256k1").getN();
		var ecKey1 = new SPEC.ECKey(privKey1);
		var ecKey2 = new SPEC.ECKey(privKey2);
		// if both keys are the same return null
		if (ecKey1.getSPECHexFormat() == ecKey2.getSPECHexFormat()) return null;
		if (ecKey1 == null || ecKey2 == null) return null;
		var combinedPrivateKey = new SPEC.ECKey(ecKey1.priv.multiply(ecKey2.priv).mod(n));
		// compressed when both keys are compressed
		if (ecKey1.compressed && ecKey2.compressed) combinedPrivateKey.setCompressed(true);
		return combinedPrivateKey;
	},
	// 58 base58 characters starting with 6P
	isBIP38Format: function (key) {
		key = key.toString();
		return (/^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(key));
	},
	BIP38EncryptedKeyToByteArrayAsync: function (base58Encrypted, passphrase, callback) {
		var hex;
		try {
			hex = SPEC.Base58.decode(base58Encrypted);
		} catch (e) {
			callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
			return;
		}

		// 43 bytes: 2 bytes prefix, 37 bytes payload, 4 bytes checksum
		if (hex.length != 43) {
			callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
			return;
		}
		// first byte is always 0x01 
		else if (hex[0] != 0x01) {
			callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
			return;
		}

		var expChecksum = hex.slice(-4);
		hex = hex.slice(0, -4);
		var checksum = SPEC.Util.dsha256(hex);
		if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
			callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
			return;
		}

		var isCompPoint = false;
		var isECMult = false;
		var hasLotSeq = false;
		// second byte for non-EC-multiplied key
		if (hex[1] == 0x42) {
			// key should use compression
			if (hex[2] == 0xe0) {
				isCompPoint = true;
			}
			// key should NOT use compression
			else if (hex[2] != 0xc0) {
				callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
				return;
			}
		}
		// second byte for EC-multiplied key 
		else if (hex[1] == 0x43) {
			isECMult = true;
			isCompPoint = (hex[2] & 0x20) != 0;
			hasLotSeq = (hex[2] & 0x04) != 0;
			if ((hex[2] & 0x24) != hex[2]) {
				callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
				return;
			}
		}
		else {
			callback(new Error(ninja.translator.get("detailalertnotvalidprivatekey")));
			return;
		}

		var decrypted;
		var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };

		var verifyHashAndReturn = function () {
			var tmpkey = new SPEC.ECKey(decrypted); // decrypted using closure
			var base58AddrText = tmpkey.setCompressed(isCompPoint).getSPECAddress(); // isCompPoint using closure
			checksum = SPEC.Util.dsha256(base58AddrText); // checksum using closure

			if (checksum[0] != hex[3] || checksum[1] != hex[4] || checksum[2] != hex[5] || checksum[3] != hex[6]) {
				callback(new Error(ninja.translator.get("bip38alertincorrectpassphrase"))); // callback using closure
				return;
			}
			callback(tmpkey.getSPECPrivateKeyByteArray()); // callback using closure
		};

		if (!isECMult) {
			var addresshash = hex.slice(3, 7);
			Crypto_scrypt(passphrase, addresshash, 16384, 8, 8, 64, function (derivedBytes) {
				var k = derivedBytes.slice(32, 32 + 32);
				decrypted = Crypto.AES.decrypt(hex.slice(7, 7 + 32), k, AES_opts);
				for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
				verifyHashAndReturn(); //TODO: pass in 'decrypted' as a param
			});
		}
		else {
			var ownerentropy = hex.slice(7, 7 + 8);
			var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
			Crypto_scrypt(passphrase, ownersalt, 16384, 8, 8, 32, function (prefactorA) {
				var passfactor;
				if (!hasLotSeq) { // hasLotSeq using closure
					passfactor = prefactorA;
				} else {
					var prefactorB = prefactorA.concat(ownerentropy); // ownerentropy using closure
					passfactor = SPEC.Util.dsha256(prefactorB);
				}
				var kp = new SPEC.ECKey(passfactor);
				var passpoint = kp.setCompressed(true).getPub();

				var encryptedpart2 = hex.slice(23, 23 + 16);

				var addresshashplusownerentropy = hex.slice(3, 3 + 12);
				Crypto_scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64, function (derived) {
					var k = derived.slice(32);

					var unencryptedpart2 = Crypto.AES.decrypt(encryptedpart2, k, AES_opts);
					for (var i = 0; i < 16; i++) { unencryptedpart2[i] ^= derived[i + 16]; }

					var encryptedpart1 = hex.slice(15, 15 + 8).concat(unencryptedpart2.slice(0, 0 + 8));
					var unencryptedpart1 = Crypto.AES.decrypt(encryptedpart1, k, AES_opts);
					for (var i = 0; i < 16; i++) { unencryptedpart1[i] ^= derived[i]; }

					var seedb = unencryptedpart1.slice(0, 0 + 16).concat(unencryptedpart2.slice(8, 8 + 8));

					var factorb = SPEC.Util.dsha256(seedb);

					var ps = EllipticCurve.getSECCurveByName("secp256k1");
					var privateKey = BigInteger.fromByteArrayUnsigned(passfactor).multiply(BigInteger.fromByteArrayUnsigned(factorb)).remainder(ps.getN());

					decrypted = privateKey.toByteArrayUnsigned();
					verifyHashAndReturn();
				});
			});
		}
	},
	BIP38PrivateKeyToEncryptedKeyAsync: function (base58Key, passphrase, compressed, callback) {
		var privKey = new SPEC.ECKey(base58Key);
		var privKeyBytes = privKey.getSPECPrivateKeyByteArray();
		var address = privKey.setCompressed(compressed).getSPECAddress();

		// compute sha256(sha256(address)) and take first 4 bytes
		var salt = SPEC.Util.dsha256(address).slice(0, 4);

		// derive key using scrypt
		var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };

		Crypto_scrypt(passphrase, salt, 16384, 8, 8, 64, function (derivedBytes) {
			for (var i = 0; i < 32; ++i) {
				privKeyBytes[i] ^= derivedBytes[i];
			}

			// 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
			var flagByte = compressed ? 0xe0 : 0xc0;
			var encryptedKey = [0x01, 0x42, flagByte].concat(salt);
			encryptedKey = encryptedKey.concat(Crypto.AES.encrypt(privKeyBytes, derivedBytes.slice(32), AES_opts));
			encryptedKey = encryptedKey.concat(SPEC.Util.dsha256(encryptedKey).slice(0, 4));
			callback(SPEC.Base58.encode(encryptedKey));
		});
	},
	BIP38GenerateIntermediatePointAsync: function (passphrase, lotNum, sequenceNum, callback) {
		var noNumbers = lotNum === null || sequenceNum === null;
		var rng = new SecureRandom();
		var ownerEntropy, ownerSalt;

		if (noNumbers) {
			ownerSalt = ownerEntropy = new Array(8);
			rng.nextBytes(ownerEntropy);
		}
		else {
			// 1) generate 4 random bytes
			ownerSalt = new Array(4);

			rng.nextBytes(ownerSalt);

			// 2)  Encode the lot and sequence numbers as a 4 byte quantity (big-endian):
			// lotnumber * 4096 + sequencenumber. Call these four bytes lotsequence.
			var lotSequence = BigInteger(4096 * lotNum + sequenceNum).toByteArrayUnsigned();

			// 3) Concatenate ownersalt + lotsequence and call this ownerentropy.
			var ownerEntropy = ownerSalt.concat(lotSequence);
		}


		// 4) Derive a key from the passphrase using scrypt
		Crypto_scrypt(passphrase, ownerSalt, 16384, 8, 8, 32, function (prefactor) {
			// Take SHA256(SHA256(prefactor + ownerentropy)) and call this passfactor
			var passfactorBytes = noNumbers ? prefactor : SPEC.Util.dsha256(prefactor.concat(ownerEntropy));
			var passfactor = BigInteger.fromByteArrayUnsigned(passfactorBytes);

			// 5) Compute the elliptic curve point G * passfactor, and convert the result to compressed notation (33 bytes)
			var ellipticCurve = EllipticCurve.getSECCurveByName("secp256k1");
			var passpoint = ellipticCurve.getG().multiply(passfactor).getEncoded(1);

			// 6) Convey ownersalt and passpoint to the party generating the keys, along with a checksum to ensure integrity.
			// magic bytes "2C E9 B3 E1 FF 39 E2 51" followed by ownerentropy, and then passpoint
			var magicBytes = [0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2, 0x51];
			if (noNumbers) magicBytes[7] = 0x53;

			var intermediate = magicBytes.concat(ownerEntropy).concat(passpoint);

			// base58check encode
			intermediate = intermediate.concat(SPEC.Util.dsha256(intermediate).slice(0, 4));
			callback(SPEC.Base58.encode(intermediate));
		});
	},
	BIP38GenerateECAddressAsync: function (intermediate, compressed, callback) {
		// decode IPS
		var x = SPEC.Base58.decode(intermediate);
		//if(x.slice(49, 4) !== SPEC.Util.dsha256(x.slice(0,49)).slice(0,4)) {
		//	callback({error: 'Invalid intermediate passphrase string'});
		//}
		var noNumbers = (x[7] === 0x53);
		var ownerEntropy = x.slice(8, 8 + 8);
		var passpoint = x.slice(16, 16 + 33);

		// 1) Set flagbyte.
		// set bit 0x20 for compressed key
		// set bit 0x04 if ownerentropy contains a value for lotsequence
		var flagByte = (compressed ? 0x20 : 0x00) | (noNumbers ? 0x00 : 0x04);


		// 2) Generate 24 random bytes, call this seedb.
		var seedB = new Array(24);
		var rng = new SecureRandom();
		rng.nextBytes(seedB);

		// Take SHA256(SHA256(seedb)) to yield 32 bytes, call this factorb.
		var factorB = SPEC.Util.dsha256(seedB);

		// 3) ECMultiply passpoint by factorb. Use the resulting EC point as a public key and hash it into a SPEC
		// address using either compressed or uncompressed public key methodology (specify which methodology is used
		// inside flagbyte). This is the generated SPEC address, call it generatedaddress.
		var ec = EllipticCurve.getSECCurveByName("secp256k1").getCurve();
		var generatedPoint = ec.decodePointHex(ninja.publicKey.getHexFromByteArray(passpoint));
		var generatedBytes = generatedPoint.multiply(BigInteger.fromByteArrayUnsigned(factorB)).getEncoded(compressed);
		var generatedAddress = (new SPEC.Address(SPEC.Util.sha256ripe160(generatedBytes))).toString();

		// 4) Take the first four bytes of SHA256(SHA256(generatedaddress)) and call it addresshash.
		var addressHash = SPEC.Util.dsha256(generatedAddress).slice(0, 4);

		// 5) Now we will encrypt seedb. Derive a second key from passpoint using scrypt
		Crypto_scrypt(passpoint, addressHash.concat(ownerEntropy), 1024, 1, 1, 64, function (derivedBytes) {
			// 6) Do AES256Encrypt(seedb[0...15]] xor derivedhalf1[0...15], derivedhalf2), call the 16-byte result encryptedpart1
			for (var i = 0; i < 16; ++i) {
				seedB[i] ^= derivedBytes[i];
			}
			var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };
			var encryptedPart1 = Crypto.AES.encrypt(seedB.slice(0, 16), derivedBytes.slice(32), AES_opts);

			// 7) Do AES256Encrypt((encryptedpart1[8...15] + seedb[16...23]) xor derivedhalf1[16...31], derivedhalf2), call the 16-byte result encryptedseedb.
			var message2 = encryptedPart1.slice(8, 8 + 8).concat(seedB.slice(16, 16 + 8));
			for (var i = 0; i < 16; ++i) {
				message2[i] ^= derivedBytes[i + 16];
			}
			var encryptedSeedB = Crypto.AES.encrypt(message2, derivedBytes.slice(32), AES_opts);

			// 0x01 0x43 + flagbyte + addresshash + ownerentropy + encryptedpart1[0...7] + encryptedpart2
			var encryptedKey = [0x01, 0x43, flagByte].concat(addressHash).concat(ownerEntropy).concat(encryptedPart1.slice(0, 8)).concat(encryptedSeedB);

			// base58check encode
			encryptedKey = encryptedKey.concat(SPEC.Util.dsha256(encryptedKey).slice(0, 4));
			callback(generatedAddress, SPEC.Base58.encode(encryptedKey));
		});
	}
};

ninja.publicKey = {
	isPublicKeyHexFormat: function (key) {
		key = key.toString();
		return ninja.publicKey.isUncompressedPublicKeyHexFormat(key) || ninja.publicKey.isCompressedPublicKeyHexFormat(key);
	},
	// 130 characters [0-9A-F] starts with 04
	isUncompressedPublicKeyHexFormat: function (key) {
		key = key.toString();
		return /^04[A-Fa-f0-9]{128}$/.test(key);
	},
	// 66 characters [0-9A-F] starts with 02 or 03
	isCompressedPublicKeyHexFormat: function (key) {
		key = key.toString();
		return /^0[2-3][A-Fa-f0-9]{64}$/.test(key);
	},
	getSPECAddressFromByteArray: function (pubKeyByteArray) {
		var pubKeyHash = SPEC.Util.sha256ripe160(pubKeyByteArray);
		var addr = new SPEC.Address(pubKeyHash);
		return addr.toString();
	},
	getHexFromByteArray: function (pubKeyByteArray) {
		return Crypto.util.bytesToHex(pubKeyByteArray).toString().toUpperCase();
	},
	getByteArrayFromAdding: function (pubKeyHex1, pubKeyHex2) {
		var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
		var curve = ecparams.getCurve();
		var ecPoint1 = curve.decodePointHex(pubKeyHex1);
		var ecPoint2 = curve.decodePointHex(pubKeyHex2);
		// if both points are the same return null
		if (ecPoint1.equals(ecPoint2)) return null;
		var compressed = (ecPoint1.compressed && ecPoint2.compressed);
		var pubKey = ecPoint1.add(ecPoint2).getEncoded(compressed);
		return pubKey;
	},
	getByteArrayFromMultiplying: function (pubKeyHex, ecKey) {
		var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
		var ecPoint = ecparams.getCurve().decodePointHex(pubKeyHex);
		var compressed = (ecPoint.compressed && ecKey.compressed);
		// if both points are the same return null
		ecKey.setCompressed(false);
		if (ecPoint.equals(ecKey.getPubPoint())) {
			return null;
		}
		var bigInt = ecKey.priv;
		var pubKey = ecPoint.multiply(bigInt).getEncoded(compressed);
		return pubKey;
	},
	// used by unit test
	getDecompressedPubKeyHex: function (pubKeyHexComp) {
		var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
		var ecPoint = ecparams.getCurve().decodePointHex(pubKeyHexComp);
		var pubByteArray = ecPoint.getEncoded(0);
		var pubHexUncompressed = ninja.publicKey.getHexFromByteArray(pubByteArray);
		return pubHexUncompressed;
	}
};













ninja.seeder = {
	init: (function () {
		document.getElementById("generatekeyinput").value = "";
	})(),

	// number of mouse movements to wait for
	seedLimit: (function () {
		var num = Crypto.util.randomBytes(12)[11];
		return 200 + Math.floor(num);
	})(),

	seedCount: 0, // counter
	lastInputTime: new Date().getTime(),
	seedPoints: [],

	// seed function exists to wait for mouse movement to add more entropy before generating an address
	seed: function (evt) {
		if (!evt) var evt = window.event;
		var timeStamp = new Date().getTime();
		// seeding is over now we generate and display the address
		if (ninja.seeder.seedCount == ninja.seeder.seedLimit) {
			ninja.seeder.seedCount++;
			ninja.wallets.singlewallet.open();
			document.getElementById("generate").style.display = "none";
			document.getElementById("menu").style.visibility = "visible";
			ninja.seeder.removePoints();
		}
		// seed mouse position X and Y when mouse movements are greater than 40ms apart.
		else if ((ninja.seeder.seedCount < ninja.seeder.seedLimit) && evt && (timeStamp - ninja.seeder.lastInputTime) > 40) {
			SecureRandom.seedTime();
			SecureRandom.seedInt16((evt.clientX * evt.clientY));
			ninja.seeder.showPoint(evt.clientX, evt.clientY);
			ninja.seeder.seedCount++;
			ninja.seeder.lastInputTime = new Date().getTime();
			ninja.seeder.showPool();
		}
	},

	// seed function exists to wait for mouse movement to add more entropy before generating an address
	seedKeyPress: function (evt) {
		if (!evt) var evt = window.event;
		// seeding is over now we generate and display the address
		if (ninja.seeder.seedCount == ninja.seeder.seedLimit) {
			ninja.seeder.seedCount++;
			ninja.wallets.singlewallet.open();
			document.getElementById("generate").style.display = "none";
			document.getElementById("menu").style.visibility = "visible";
			ninja.seeder.removePoints();
		}
		// seed key press character
		else if ((ninja.seeder.seedCount < ninja.seeder.seedLimit) && evt.which) {
			var timeStamp = new Date().getTime();
			// seed a bunch (minimum seedLimit) of times
			SecureRandom.seedTime();
			SecureRandom.seedInt8(evt.which);
			var keyPressTimeDiff = timeStamp - ninja.seeder.lastInputTime;
			SecureRandom.seedInt8(keyPressTimeDiff);
			ninja.seeder.seedCount++;
			ninja.seeder.lastInputTime = new Date().getTime();
			ninja.seeder.showPool();
		}
	},

	showPool: function () {
		var poolHex;
		if (SecureRandom.poolCopyOnInit != null) {
			poolHex = Crypto.util.bytesToHex(SecureRandom.poolCopyOnInit);
			document.getElementById("seedpool").innerHTML = poolHex;
			document.getElementById("seedpooldisplay").innerHTML = poolHex;
		}
		else {
			poolHex = Crypto.util.bytesToHex(SecureRandom.pool);
			document.getElementById("seedpool").innerHTML = poolHex;
			document.getElementById("seedpooldisplay").innerHTML = poolHex;
		}
		document.getElementById("mousemovelimit").innerHTML = (ninja.seeder.seedLimit - ninja.seeder.seedCount);
	},

	showPoint: function (x, y) {
		var div = document.createElement("div");
		div.setAttribute("class", "seedpoint");
		div.style.top = y + "px";
		div.style.left = x + "px";
		document.body.appendChild(div);
		ninja.seeder.seedPoints.push(div);
	},

	removePoints: function () {
		for (var i = 0; i < ninja.seeder.seedPoints.length; i++) {
			document.body.removeChild(ninja.seeder.seedPoints[i]);
		}
		ninja.seeder.seedPoints = [];
	}
};

ninja.qrCode = {
	// determine which type number is big enough for the input text length
	getTypeNumber: function (text) {
		var lengthCalculation = text.length * 8 + 12; // length as calculated by the QRCode
		if (lengthCalculation < 72) { return 1; }
		else if (lengthCalculation < 128) { return 2; }
		else if (lengthCalculation < 208) { return 3; }
		else if (lengthCalculation < 288) { return 4; }
		else if (lengthCalculation < 368) { return 5; }
		else if (lengthCalculation < 480) { return 6; }
		else if (lengthCalculation < 528) { return 7; }
		else if (lengthCalculation < 688) { return 8; }
		else if (lengthCalculation < 800) { return 9; }
		else if (lengthCalculation < 976) { return 10; }
		return null;
	},

	createCanvas: function (text, sizeMultiplier) {
		sizeMultiplier = (sizeMultiplier == undefined) ? 2 : sizeMultiplier; // default 2
		// create the qrcode itself
		var typeNumber = ninja.qrCode.getTypeNumber(text);
		var qrcode = new QRCode(typeNumber, QRCode.ErrorCorrectLevel.H);
		qrcode.addData(text);
		qrcode.make();
		var width = qrcode.getModuleCount() * sizeMultiplier;
		var height = qrcode.getModuleCount() * sizeMultiplier;
		// create canvas element
		var canvas = document.createElement('canvas');
		var scale = 10.0;
		canvas.width = width * scale;
		canvas.height = height * scale;
		canvas.style.width = width + 'px';
		canvas.style.height = height + 'px';
		var ctx = canvas.getContext('2d');
		ctx.scale(scale, scale);
		// compute tileW/tileH based on width/height
		var tileW = width / qrcode.getModuleCount();
		var tileH = height / qrcode.getModuleCount();
		// draw in the canvas
		for (var row = 0; row < qrcode.getModuleCount(); row++) {
			for (var col = 0; col < qrcode.getModuleCount(); col++) {
				ctx.fillStyle = qrcode.isDark(row, col) ? "#000000" : "#ffffff";
				ctx.fillRect(col * tileW, row * tileH, tileW, tileH);
			}
		}
		// return just built canvas
		return canvas;
	},

	// generate a QRCode and return it's representation as an Html table 
	createTableHtml: function (text) {
		var typeNumber = ninja.qrCode.getTypeNumber(text);
		var qr = new QRCode(typeNumber, QRCode.ErrorCorrectLevel.H);
		qr.addData(text);
		qr.make();
		var tableHtml = "<table class='qrcodetable'>";
		for (var r = 0; r < qr.getModuleCount(); r++) {
			tableHtml += "<tr>";
			for (var c = 0; c < qr.getModuleCount(); c++) {
				if (qr.isDark(r, c)) {
					tableHtml += "<td class='qrcodetddark'/>";
				} else {
					tableHtml += "<td class='qrcodetdlight'/>";
				}
			}
			tableHtml += "</tr>";
		}
		tableHtml += "</table>";
		return tableHtml;
	},

	// show QRCodes with canvas OR table (IE8)
	// parameter: keyValuePair 
	// example: { "id1": "string1", "id2": "string2"}
	//		"id1" is the id of a div element where you want a QRCode inserted.
	//		"string1" is the string you want encoded into the QRCode.
	showQrCode: function (keyValuePair, sizeMultiplier) {
		for (var key in keyValuePair) {
			var value = keyValuePair[key];
			try {
				if (document.getElementById(key)) {
					document.getElementById(key).innerHTML = "";
					document.getElementById(key).appendChild(ninja.qrCode.createCanvas(value, sizeMultiplier));
				}
			}
			catch (e) {
				// for browsers that do not support canvas (IE8)
				document.getElementById(key).innerHTML = ninja.qrCode.createTableHtml(value);
			}
		}
	}
};

ninja.tabSwitch = function (walletTab) {
	if (walletTab.className.indexOf("selected") == -1) {
		// unselect all tabs
		for (var wType in ninja.wallets) {
			document.getElementById(wType).className = "tab";
			ninja.wallets[wType].close();
		}
		walletTab.className += " selected";
		ninja.wallets[walletTab.getAttribute("id")].open();
	}
};

ninja.getQueryString = function () {
	var result = {}, queryString = location.search.substring(1), re = /([^&=]+)=([^&]*)/g, m;
	while (m = re.exec(queryString)) {
		result[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
	}
	return result;
};

// use when passing an Array of Functions
ninja.runSerialized = function (functions, onComplete) {
	onComplete = onComplete || function () { };

	if (functions.length === 0) onComplete();
	else {
		// run the first function, and make it call this
		// function when finished with the rest of the list
		var f = functions.shift();
		f(function () { ninja.runSerialized(functions, onComplete); });
	}
};

ninja.forSerialized = function (initial, max, whatToDo, onComplete) {
	onComplete = onComplete || function () { };

	if (initial === max) { onComplete(); }
	else {
		// same idea as runSerialized
		whatToDo(initial, function () { ninja.forSerialized(++initial, max, whatToDo, onComplete); });
	}
};

// use when passing an Object (dictionary) of Functions
ninja.foreachSerialized = function (collection, whatToDo, onComplete) {
	var keys = [];
	for (var name in collection) {
		keys.push(name);
	}
	ninja.forSerialized(0, keys.length, function (i, callback) {
		whatToDo(keys[i], callback);
	}, onComplete);
};