import * as forge from 'node-forge';

/**
 * Generate a random AES key.
 * @param keySize The size of the AES key.
 * @returns Base64-encoded string representation of the generated AES key.
 */
export const generateAesKey = (keySize: number = 256): string => {
  const array = new Uint8Array(keySize / 8);
  crypto.getRandomValues(array);
  return encodeUint8ArrayToBase64(array);
};
/**
 * Generates an RSA key pair (public and private keys).
 * @returns An object containing the RSA public and private keys.
 */
export const generateRSAKeyPair = async (): Promise<{ publicKey: string; privateKey: string }> => {
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

  // Convert public key to base64 string
  const publicKey = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPublicKey))));

  // Export private key
  const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keys.privateKey);

  // Convert private key to base64 string
  const privateKey = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPrivateKey))));

  return { publicKey, privateKey };
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
  const key = await crypto.subtle.importKey(keyFormat, decodeBase64ToUint8Array(publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
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
  const key = await crypto.subtle.importKey(keyFormat, decodeBase64ToUint8Array(privateKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
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
export const hybridEncryptor = async (plaintext: string, publicKeyPem: string): Promise<string> => {
  // Read the RSA public key from PEM format
  const publicKey = readRsaKeyFromPem(publicKeyPem);

  // Generate a random AES key
  const aesKey = await aesKeyGenerate();

  // Generate a random initialization vector (IV)
  const iv = await generateIv(); // IV size: 128 bits

  // Encrypt the plaintext using AES encryption
  const encryptedAesData = await encryptWithAes(plaintext, aesKey, iv);

  // Encrypt the AES key with RSA
  const encryptedAesKey = encryptAesKeyWithRsa(aesKey, publicKey);

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
export const hybridDecryptor = async (encryptedBase64String: string, privateKeyPem: string): Promise<string> => {
  // Decode Base64 and split the concatenated Uint8Array
  const [iv, encryptedData, encryptedAesKey] = await decodeBase64AndSplitUint8Arrays(encryptedBase64String, 16, 256);

  // Read RSA private key from PEM
  const privateKey = readPrivateKeyFromPem(privateKeyPem);

  // Decrypt the AES key with RSA
  const decryptedAesKey = decryptAesKeyWithRsa(encryptedAesKey, privateKey);

  // Decrypt the data with AES
  const decryptedData = await decryptWithAes(encryptedData, decryptedAesKey, iv);

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
const encodeUint8ArrayToBase64 = (array: Uint8Array): string => {
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
const decodeBase64ToUint8Array = (base64String: string): Uint8Array => {
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
 * Reads an RSA public key from a PEM formatted string.
 *
 * @param publicKeyPem - The PEM formatted string containing the RSA public key.
 * @returns The RSA public key object.
 */
const readRsaKeyFromPem = (publicKeyPem: string): forge.pki.rsa.PublicKey => {
  // Parse the PEM formatted string to obtain the public key object
  const pemObject = forge.pki.publicKeyFromPem(publicKeyPem);

  // Return the RSA public key object
  return pemObject;
}

/**
 * Encrypts an AES key using RSA with ECB and PKCS1 padding.
 *
 * @param aesKey - The AES key to be encrypted as a Uint8Array.
 * @param publicKey - The RSA public key used for encryption.
 * @returns The encrypted AES key as a Uint8Array.
 */
const encryptAesKeyWithRsa = (aesKey: Uint8Array, publicKey: forge.pki.rsa.PublicKey): Uint8Array => {
  // Convert Uint8Array to a binary string
  // This step transforms each byte in the AES key into its corresponding character representation
  let binaryString = '';
  for (let i = 0; i < aesKey.length; i++) {
    binaryString += String.fromCharCode(aesKey[i]);
  }

  // Encrypt the binary string AES key with RSA using RSAES-PKCS1-V1_5 padding
  // This encryption method uses RSA encryption with the public key provided
  const encryptedBinaryString = publicKey.encrypt(binaryString, 'RSAES-PKCS1-V1_5');

  // Convert the encrypted binary string back to a Uint8Array
  // This step involves creating a new Uint8Array and filling it with the encrypted data
  const encryptedArrayBuffer = new ArrayBuffer(encryptedBinaryString.length);
  const encryptedUint8Array = new Uint8Array(encryptedArrayBuffer);
  for (let i = 0; i < encryptedBinaryString.length; i++) {
    encryptedUint8Array[i] = encryptedBinaryString.charCodeAt(i);
  }

  // Return the encrypted AES key as a Uint8Array
  return encryptedUint8Array;
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
 * Reads an RSA private key from PEM format.
 * 
 * @param {string} privateKeyPem - The PEM-encoded RSA private key.
 * @returns {forge.pki.rsa.PrivateKey} - The RSA private key.
 */
const readPrivateKeyFromPem = (privateKeyPem: string): forge.pki.rsa.PrivateKey => {
  return forge.pki.privateKeyFromPem(privateKeyPem) as forge.pki.rsa.PrivateKey;
}

/**
 * Decrypts an AES key using RSA decryption.
 * 
 * @param {Uint8Array} encryptedAesKey - The encrypted AES key.
 * @param {forge.pki.rsa.PrivateKey} privateKey - The RSA private key.
 * @returns {Uint8Array} - The decrypted AES key.
 */
const decryptAesKeyWithRsa = (encryptedAesKey: Uint8Array, privateKey: forge.pki.rsa.PrivateKey): Uint8Array => {
  let encryptedBinaryString = '';
  for (let i = 0; i < encryptedAesKey.length; i++) {
    encryptedBinaryString += String.fromCharCode(encryptedAesKey[i]);
  }

  const decryptedBinaryString = privateKey.decrypt(encryptedBinaryString, 'RSAES-PKCS1-V1_5');

  const decryptedUint8Array = new Uint8Array(decryptedBinaryString.length);
  for (let i = 0; i < decryptedBinaryString.length; i++) {
    decryptedUint8Array[i] = decryptedBinaryString.charCodeAt(i);
  }

  return decryptedUint8Array;
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
