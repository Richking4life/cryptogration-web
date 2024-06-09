
/**
 * Generates an RSA key pair and wraps the private key using the provided passphrase.
 * 
 * @param {string} passphrase - The passphrase used to wrap the private key.
 * @returns {Promise<{ publicKey: string; wrappedPrivateKey: string; salt: string; iv: string }>} - A promise that resolves to the public key, wrapped private key, salt, and IV.
 */
export const generateAndWrapRSAKeyPair = async (passphrase: string): Promise<{ publicKey: string; wrappedPrivateKey: string; salt: string; iv: string }> => {
  // Generate RSA key pair
  const keys = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048, // 2048-bit key size
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // Exponent value (65537)
      hash: { name: 'SHA-256' }, // Hash function
    },
    true, // Whether the key is extractable (true for export)
    ['encrypt', 'decrypt'] // Key usage
  );

  // Export public key
  const exportedPublicKey = await crypto.subtle.exportKey('spki', keys.publicKey);
  const publicKey = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPublicKey))));

  // Export private key
  //const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keys.privateKey);
  //const privateKey = new Uint8Array(exportedPrivateKey);

  // Create a key for wrapping the private key using the passphrase
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive an AES key from the passphrase key
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['wrapKey', 'unwrapKey']
  );

  // Wrap (encrypt) the private key using the wrapping key
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedPrivateKey = await crypto.subtle.wrapKey(
    'pkcs8',
    keys.privateKey,
    wrappingKey,
    { name: 'AES-GCM', iv: iv }
  );

  // Convert wrapped private key, salt, and IV to base64 string
  const wrappedPrivateKeyBase64 = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(wrappedPrivateKey))));
  const saltBase64 = btoa(String.fromCharCode.apply(null, Array.from(salt)));
  const ivBase64 = btoa(String.fromCharCode.apply(null, Array.from(iv)));

  return { publicKey, wrappedPrivateKey: wrappedPrivateKeyBase64, salt: saltBase64, iv: ivBase64 };
};



/**
 * Encrypts data using AES encryption.
 * @param data The data to be encrypted.
 * @param aesKey The AES key used for encryption.
 * @returns An object containing the encrypted data and the IV used for encryption.
 */
export const aesEncryptor = async (data: string, aesKey: string): Promise<{ encryptedData: Uint8Array; iv: Uint8Array }> => {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encodedData = new TextEncoder().encode(data);
  const algorithm = { name: 'AES-CBC', iv };
  const key = await crypto.subtle.importKey('raw', decodeBase64ToUint8Array(aesKey), algorithm, false, ['encrypt']);
  const encryptedBuffer = await crypto.subtle.encrypt(algorithm, key, encodedData);
  return { encryptedData: new Uint8Array(encryptedBuffer), iv: iv };
};
/**
 * Decrypts data using AES decryption.
 * @param encryptedData The encrypted data to be decrypted.
 * @param aesKey The AES key used for decryption.
 * @param iv The initialization vector (IV) used for encryption.
 * @returns The decrypted data.
 */
export const aesDecryptor = async (encryptedData: Uint8Array, aesKey: string, iv: Uint8Array): Promise<string> => {
  const algorithm = { name: 'AES-CBC', iv: iv };
  const key = await crypto.subtle.importKey('raw', decodeBase64ToUint8Array(aesKey), algorithm, false, ['decrypt']);
  const decryptedBuffer = await crypto.subtle.decrypt(algorithm, key, encryptedData);
  return new TextDecoder().decode(decryptedBuffer);
};
/**
 * Encrypts an AES key using RSA encryption.
 * @param aesKey The AES key to be encrypted.
 * @param publicKey The RSA public key used for encryption.
 * @param keyFormat The format of the RSA public key (default: 'spki').
 * @returns Base64-encoded string representation of the encrypted AES key.
 */
export const rsaEncryptor = async (aesKey: string, publicKey: string, keyFormat: 'spki' | 'raw' = 'spki'): Promise<Uint8Array> => {
  const encodedKey = new TextEncoder().encode(aesKey);
  const key = await crypto.subtle.importKey(keyFormat, pemToUint8Array(publicKey) as Uint8Array, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const encryptedBuffer = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, encodedKey);
  return new Uint8Array(encryptedBuffer);
};
/**
 * Decrypts an AES key using RSA decryption.
 * @param encryptedAesKey The encrypted AES key to be decrypted.
 * @param privateKey The RSA private key used for decryption.
 * @param keyFormat The format of the RSA private key (default: 'pkcs8').
 * @returns The decrypted AES key.
 */
export const rsaDecryptor = async (encryptedAesKey: Uint8Array, privateKey: string, keyFormat: 'pkcs8' | 'raw' = 'pkcs8'): Promise<string> => {
  const key = await crypto.subtle.importKey(keyFormat, pemToUint8Array(privateKey) as Uint8Array, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const decryptedBuffer = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, encryptedAesKey);
  return new TextDecoder().decode(decryptedBuffer);
};
/**
 * Encrypts plaintext using a hybrid encryption scheme combining AES and RSA.
 * The AES key is randomly generated, and the AES key is encrypted using RSA.
 * The encrypted AES key, IV, and encrypted data are concatenated and encoded to Base64.
 *
 * @param plaintext - The plaintext to encrypt.
 * @param publicKeyPem - The RSA public key in PEM format used for encryption.
 * @returns A Promise resolving to the Base64-encoded encrypted data.
 */
export const hybridEncryptAsync = async (plaintext: string, publicKeyPem: string): Promise<string> => {
  // Read the RSA public key from PEM format
  //const publicKey = readRsaKeyFromPem(publicKeyPem);

  // Generate a random AES key
  const aesKey = await aesKeyGenerate();

  // Generate a random initialization vector (IV)
  const iv = await generateIv(); // IV size: 128 bits

  // Encrypt the plaintext using AES encryption
  const encryptedAesData = await encryptWithAes(plaintext, aesKey, iv);

  // Encrypt the AES key with RSA
  const encryptedAesKey = await rsaEncryptor(encodeUint8ArrayToBase64(aesKey), publicKeyPem);

  // Concatenate the IV, encrypted AES data, and encrypted AES key, and encode to Base64
  return concatenateUint8ArraysAndEncodeBase64([iv, encryptedAesData, encryptedAesKey]);
}

/**
 * Decrypts a Base64-encoded string that was encrypted using hybrid AES and RSA encryption.
 * 
 * @param {string} encryptedBase64String - The Base64-encoded string to decrypt.
 * @param {string} privateKeyPem - The PEM-encoded RSA private key.
 * @returns {Promise<string>} - The decrypted plaintext.
 */
export const hybridDecryptorAsync = async (encryptedBase64String: string, privateKeyPem: string): Promise<string> => {
  // Decode Base64 and split the concatenated Uint8Array
  const [iv, encryptedData, encryptedAesKey] = await decodeBase64AndSplitUint8Arrays(encryptedBase64String, 16, 256);

  // Read RSA private key from PEM
  //const privateKey = readPrivateKeyFromPem(privateKeyPem);

  // Decrypt the AES key with RSA
  const decryptedAesKey = await rsaDecryptor(encryptedAesKey, privateKeyPem);

  // Decrypt the data with AES
  const decryptedData = await decryptWithAes(encryptedData, decodeBase64ToUint8Array(decryptedAesKey) as Uint8Array, iv);

  return decryptedData;
};

/**
 * Generates an array of random bytes using the Web Crypto API.
 *
 * @param length - The length of the array to generate.
 * @returns An array of random bytes as a Uint8Array.
 */
const generateRandomBytes = (length: number): Uint8Array => {
  // Create a new Uint8Array with the specified length
  const buffer = new Uint8Array(length);

  // Fill the buffer with random values using the Web Crypto API
  window.crypto.getRandomValues(buffer);

  // Return the generated random bytes
  return buffer;
}

/**
 * Generates a random AES key.
 *
 * @returns A random AES key as a Uint8Array.
 */
const aesKeyGenerate = (): Uint8Array => {
  // Generate a random AES key with a length of 32 bytes (256 bits)
  return generateRandomBytes(32);
}

/**
 * Generates a random initialization vector (IV) for AES encryption.
 *
 * @returns A random IV as a Uint8Array.
 */
const generateIv = (): Uint8Array => {
  // Generate a random IV with a length of 16 bytes (128 bits)
  return generateRandomBytes(16);
}

/**
 * Encrypts plaintext using AES encryption with the provided key and IV.
 *
 * @param plaintext - The plaintext to encrypt.
 * @param key - The AES key used for encryption.
 * @param iv - The initialization vector (IV) used for encryption.
 * @returns The encrypted ciphertext as a Uint8Array.
 */
export const encryptWithAes = async (plaintext: string, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> => {
  // Encode the plaintext string to a Uint8Array
  const encodedText = new TextEncoder().encode(plaintext);

  // Import the AES key into the crypto module
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw', // The key format is raw bytes
    key,   // The AES key as raw bytes
    { name: 'AES-CBC' }, // The algorithm is AES-CBC
    false, // The key is not extractable
    ['encrypt'] // The key can be used for encryption
  );

  // Encrypt the plaintext using AES-CBC with the provided IV
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-CBC', iv }, // Use AES-CBC mode with the provided IV
    cryptoKey,              // Use the imported AES key for encryption
    encodedText             // Encrypt the plaintext
  );

  // Return the encrypted ciphertext as a Uint8Array
  return new Uint8Array(encrypted);
}

/**
 * Helper function to encode Uint8Array to Base64.
 * @param array The Uint8Array to be encoded.x
 * @returns Base64-encoded string.
 */
export const encodeUint8ArrayToBase64 = (array: Uint8Array): string => {
  // Convert Uint8Array to regular array
  const byteArray = Array.from(array);
  // Create a binary string from the byte array
  const binaryString = String.fromCharCode(...byteArray);
  // Encode the binary string to Base64
  return btoa(binaryString);
};

/**
 * Decodes a Base64 string to a Uint8Array.
 *
 * @param {string} base64String - The Base64 string to decode.
 * @returns {Uint8Array} - The decoded Uint8Array.
 */
export const decodeBase64ToUint8Array = (base64String: string): Uint8Array => {
  try {
    // Decode the Base64 string and convert it to a Uint8Array
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
  } catch (error) {
    // Handle decoding errors
    console.error('Error decoding Base64 string:', error);
    throw error;
  }
};
/**
 * Converts a Base64 string to a Uint8Array.
 *
 * @param {string} base64 - The Base64 string to convert.
 * @returns {Uint8Array} - The resulting Uint8Array.
 */
const concatenateUint8ArraysAndEncodeBase64 = async (arrays: Uint8Array[]): Promise<string> => {
  // Calculate total length
  // const totalLength = arrays.reduce((acc, array) => acc + array.length, 0);

  // Create Blob object
  const blob = new Blob(arrays, { type: 'application/octet-stream' });

  // Convert Blob to Uint8Array
  const concatenatedArray = new Uint8Array(await blob.arrayBuffer());

  // Convert Uint8Array to binary string
  let binaryString = '';
  concatenatedArray.forEach(byte => {
    binaryString += String.fromCharCode(byte);
  });

  // Encode binary string to Base64
  return btoa(binaryString);
}

/**
 * Decrypts data using AES decryption.
 *
 * @param {Uint8Array} encryptedData - The encrypted data.
 * @param {Uint8Array} aesKey - The AES key.
 * @param {Uint8Array} iv - The initialization vector.
 * @returns {Promise<string>} - The decrypted data as a string.
 */
export const decryptWithAes = async (encryptedData: Uint8Array, aesKey: Uint8Array, iv: Uint8Array): Promise<string> => {
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    aesKey,
    { name: 'AES-CBC' },
    false,
    ['decrypt']
  );
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    encryptedData
  );
  return new TextDecoder().decode(decryptedBuffer);
};
/**
 * Decodes a Base64 string and splits it into IV, encrypted AES key, and encrypted data.
 *
 * @param {string} base64String - The Base64-encoded string.
 * @param {number} ivLength - The length of the IV.
 * @param {number} keyLength - The length of the encrypted AES key.
 * @returns {Promise<Uint8Array[]>} - An array containing the IV, encrypted AES key, and encrypted data.
 */
const decodeBase64AndSplitUint8Arrays = async (base64String: string, ivLength: number, keyLength: number): Promise<Uint8Array[]> => {
  const binaryString = atob(base64String);
  const concatenatedArray = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    concatenatedArray[i] = binaryString.charCodeAt(i);
  }

  if (concatenatedArray.length < ivLength + keyLength) {
    throw new Error("Invalid concatenatedArray length");
  }

  const aesIv = concatenatedArray.subarray(0, ivLength);
  const encryptedAesData = concatenatedArray.subarray(ivLength, concatenatedArray.length - keyLength);
  const encryptedAesKey = concatenatedArray.subarray(concatenatedArray.length - keyLength);

  return [aesIv, encryptedAesData, encryptedAesKey];
};


/**
 * Converts a PEM-formatted string (public key or unencrypted private key) to a Uint8Array.
 * 
 * **Security Warning:** This function does not handle passphrase-protected private keys 
 * due to security concerns. It's strongly recommended to avoid using unencrypted private keys 
 * in browser environments. Consider secure key management solutions for private keys.
 *
 * @param pemString The PEM-formatted string containing the key data.
 * @returns A Uint8Array representing the decoded key data, or null if the format is invalid.
 */
const pemToUint8Array = (pemString: string): Uint8Array | null => {
  // Check for Private Key (unencrypted) format
  if (pemString.includes('-----BEGIN PRIVATE KEY-----') || pemString.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    console.warn('**Security Warning:** Handling unencrypted private keys in a browser is not recommended.');
    return parsePemPrivateKey(pemString);
  }



  // Check for Public Key format
  else if (pemString.includes('-----BEGIN PUBLIC KEY-----')) {
    return parsePemPublicKey(pemString);
  }

  // Invalid format
  else {
    console.error('Invalid PEM format');
    return null;
  }
};

/**
 * Parses a PEM-formatted unencrypted private key and returns a Uint8Array.
 *
 * @param pemString The PEM-formatted string containing the private key.
 * @returns A Uint8Array representing the decoded private key data, or null if parsing fails.
 */
const parsePemPrivateKey = (pemString: string): Uint8Array | null => {

  // Remove header/footer and decode base64
  const strippedPem = pemString.replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/-----BEGIN ENCRYPTED PRIVATE KEY-----/, '')
    .replace(/-----END ENCRYPTED PRIVATE KEY-----/, '');

  const base64Decoded = atob(strippedPem);

  // Convert base64 decoded string to Uint8Array
  return new Uint8Array(base64Decoded.length).fill(0).map((_, i) => base64Decoded.charCodeAt(i));
};

/**
 * Parses a PEM-formatted public key and returns a Uint8Array.
 *
 * @param pemString The PEM-formatted string containing the public key.
 * @returns A Uint8Array representing the decoded public key data, or null if parsing fails.
 */
const parsePemPublicKey = (pemString: string): Uint8Array | null => {
  // Remove header/footer and decode base64
  const strippedPem = pemString.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '');
  const base64Decoded = atob(strippedPem);

  // Convert base64 decoded string to Uint8Array
  return new Uint8Array(base64Decoded.length).fill(0).map((_, i) => base64Decoded.charCodeAt(i));
};

/**
 * Decrypts a wrapped private key using the provided passphrase, salt, and IV.
 * 
 * @param {string} wrappedPrivateKeyBase64 - The wrapped private key in base64 format.
 * @param {string} passphrase - The passphrase used to encrypt the private key.
 * @param {string} saltBase64 - The salt in base64 format.
 * @param {string} ivBase64 - The initialization vector (IV) in base64 format.
 * @param {number} modulusLength - The modulus length used for RSA key generation (e.g., 2048).
 * @returns {Promise<CryptoKey>} - A promise that resolves to the decrypted private key.
 */
export const decryptPrivateKey = async (
  wrappedPrivateKeyBase64: string,
  passphrase: string,
  saltBase64: string,
  ivBase64: string,
): Promise<CryptoKey> => {
  // Convert base64 strings to Uint8Array
  const wrappedPrivateKey = Uint8Array.from(atob(wrappedPrivateKeyBase64), c => c.charCodeAt(0));
  const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));

  // Import the passphrase as a key using PBKDF2
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive the AES-GCM key from the passphrase key
  const unwrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['unwrapKey']
  );

  // Unwrap (decrypt) the private key using the AES-GCM unwrapping key
  const privateKey = await crypto.subtle.unwrapKey(
    'pkcs8',
    wrappedPrivateKey,
    unwrappingKey,
    { name: 'AES-GCM', iv: iv },
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['decrypt']
  );

  return privateKey;
};
/**
 * Converts a CryptoKey object to a PEM-encoded private key.
 * 
 * @param {CryptoKey} cryptoKey - The CryptoKey object to convert.
 * @returns {Promise<string>} - A promise that resolves to the PEM-encoded private key.
 */
export const cryptoKeyToPem = async (cryptoKey: CryptoKey): Promise<string> => {

  // Export the CryptoKey to PKCS8 format
  const exported = await crypto.subtle.exportKey('pkcs8', cryptoKey);

  // Convert the exported key to a base64 string
  const exportedAsBase64 = btoa(String.fromCharCode(...new Uint8Array(exported)));

  // Format the base64 string as a PEM-encoded key
  const pemKey = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----`;

  return pemKey;
};

/**
 * Generates a random password with a specified length and character set.
 *
 * @param {number} length - The desired length of the password (recommended to be at least 12 characters).
 * @param {boolean} includeUppercase - Whether to include uppercase letters in the password (default: true).
 * @param {boolean} includeLowercase - Whether to include lowercase letters in the password (default: true).
 * @param {boolean} includeNumbers - Whether to include numbers in the password (default: true).
 * @param {boolean} includeSymbols - Whether to include symbols in the password (default: true).
 * @returns {string} - The generated random password.
 */
export const generateRandomPassword = (
  length: number = 12,
  includeUppercase = true,
  includeLowercase = true,
  includeNumbers = true,
  includeSymbols = true
): string => {
  let characterSet = '';

  if (includeUppercase) {
    characterSet += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  }
  if (includeLowercase) {
    characterSet += 'abcdefghijklmnopqrstuvwxyz';
  }
  if (includeNumbers) {
    characterSet += '0123456789';
  }
  if (includeSymbols) {
    characterSet += '!@#$%^&*()-_=+[]{};:,<.>/?';
  }

  if (!characterSet) {
    throw new Error('At least one character set must be included.');
  }

  let password = '';
  for (let i = 0; i < length; i++) {
    password += characterSet.charAt(Math.floor(Math.random() * characterSet.length));
  }

  return password;
};
