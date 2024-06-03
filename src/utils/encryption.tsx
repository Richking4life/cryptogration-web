

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
 * Encrypts the provided data using AES encryption and encrypts the AES key using RSA encryption.
 * @param data The data to be encrypted.
 * @param publicKey The RSA public key used for encrypting the AES key.
 * @returns An object containing the encrypted data, the IV used for encryption, and the encrypted AES key.
 */
export const hybridEncryptor = async (data: string, publicKey: string) => {
  // Generate AES key
  const aesKey = generateAesKey();

  // Encrypt data using AES
  const { encryptedData, iv } = await aesEncryptor(data, aesKey);

  publicKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt49eymH2PzNX7D9/iU2hX09GKKrE5wBBWE8psGf46+u6Ml48L8zPLlWGUAd4nRqf7YJs/M1OaAm7j02Nx3zJFxKmJqkSo3G7inv4CUI344FYAAyzsBHVMQzFGfVBpeDTw5BpbkbnOg/MgwkO5RV1oK4/Dryb6k1jwPhB/AuqGBxirfsDPgkY3irOQi0DJQMMcxurUYohkl8E3WP4ghZx4HKRym9v3hZ6CFI2l72f+69PdtyjzpU7vDpfc0uLrNX0uu1AIuEMFM1rC6qgIP+fns7F91vcJOzaHH1ZyJERJcXXP0mX81bmOmefS9tRGWyziE9jJKjIz3cyQwD8+0aH/QIDAQAB';
  // Encrypt AES key using RSA
  const encryptedAesKey = await rsaEncryptor(aesKey, publicKey);

  // Usage example:
  return concatenateUint8ArraysAndEncodeBase64([iv, encryptedData, encryptedAesKey]);
};

/**
 * Decrypts the provided data using AES decryption and the provided AES key decrypted using RSA decryption.
 * @param encryptedData The encrypted data to be decrypted.
 * @param iv The initialization vector (IV) used for encryption.
 * @param encryptedAesKey The encrypted AES key.
 * @param privateKey The RSA private key used for decrypting the AES key.
 * @returns The decrypted data.
 */
export const hybridDecryptor = async (combinedData: string, privateKey: string): Promise<string> => {

  // Split combinedData into encryptedData, iv, and encryptedAesKey
  const result = splitEncryptedData(combinedData);

  // Decrypt AES key using RSA
  const aesKey = await rsaDecryptor(result.encryptedAesKey, privateKey);

  // Decrypt data using AES
  const decryptedData = await aesDecryptor(result.encryptedAesData, aesKey, result.aesIv);

  return decryptedData;
};
/**
 * Splits a combined Uint8Array into an array of strings.
 *
 * @param {Uint8Array} combinedData - The combined data containing multiple encoded strings.
 * @returns {string[]} - An array of decoded strings.
 */
export const splitUint8Arrays = (combinedData: Uint8Array): string[] => {
  const arrays: string[] = [];
  let offset = 0;

  // Iterate over the combinedData array and split it into separate Uint8Arrays or strings.
  while (offset < combinedData.length) {
    // The first byte at the current offset indicates the length of the next array.
    const nextArrayLength = combinedData[offset++];

    // If the next array length is 0, push an empty string to the result array.
    if (nextArrayLength === 0) {
      arrays.push('');
    } else {
      // Extract and decode the next array directly in the push statement.
      arrays.push(decodeUint8ArrayToString(combinedData.subarray(offset, offset + nextArrayLength)));
      // Move the offset to the start of the next array segment.
      offset += nextArrayLength;
    }
  }
  return arrays;
};


export const hybridAesAndRsaEncryption = async (plaintext: string, publicKeyPem: string): Promise<string> => {
  const publicKey = readRsaKeyFromPem(publicKeyPem);

  const aesKey = await aesKeyGenerate();
  const iv = await generateIv(); // IV size: 128 bits


  const encryptedAesData = await encryptWithAes(plaintext, aesKey, iv);

  const encryptedAesKey = encryptAesKeyWithRsa(aesKey, publicKey);

  //const encryptedData = concatenateUint8Arrays([iv, encryptedAesData, encryptedAesKey]);

  return concatenateUint8ArraysAndEncodeBase64([iv, encryptedAesData, encryptedAesKey]);
}

function generateRandomBytes(length: number): Uint8Array {
  const buffer = new Uint8Array(length);
  window.crypto.getRandomValues(buffer);
  return buffer;
}

function aesKeyGenerate(): Uint8Array {
  return generateRandomBytes(32); // 32 bytes for AES-256
}

function generateIv(): Uint8Array {
  return generateRandomBytes(16); // 16 bytes for IV
}

async function encryptWithAes(plaintext: string, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const encodedText = new TextEncoder().encode(plaintext);
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    encodedText
  );
  return new Uint8Array(encrypted);
}



function encryptAesKeyWithRsa(aesKey: Uint8Array, publicKey: forge.pki.rsa.PublicKey): Uint8Array {
  // Convert Uint8Array to binary string
  let binaryString = '';
  for (let i = 0; i < aesKey.length; i++) {
    binaryString += String.fromCharCode(aesKey[i]);
  }

  // Encrypt the binary string AES key with RSA/ECB/PKCS1Padding
  const encryptedBinaryString = publicKey.encrypt(binaryString, 'RSAES-PKCS1-V1_5');

  // Convert the encrypted binary string back to a Uint8Array
  const encryptedArrayBuffer = new ArrayBuffer(encryptedBinaryString.length);
  const encryptedUint8Array = new Uint8Array(encryptedArrayBuffer);
  for (let i = 0; i < encryptedBinaryString.length; i++) {
    encryptedUint8Array[i] = encryptedBinaryString.charCodeAt(i);
  }

  return encryptedUint8Array;
}
// function encryptAesKeyWithRsa(aesKey: Uint8Array, publicKey: forge.pki.rsa.PublicKey): Uint8Array {
//   // Convert Uint8Array to binary string
//   let binaryString = '';
//   for (let i = 0; i < aesKey.length; i++) {
//     binaryString += String.fromCharCode(aesKey[i]);
//   }

//   // Encrypt the binary string AES key with RSA
//   const encryptedBinaryString = publicKey.encrypt(binaryString, 'RSA-OAEP', {
//     md: forge.md.sha256.create(),
//     mgf1: {
//       md: forge.md.sha256.create()
//     }
//   });

//   // Convert the encrypted binary string back to a Uint8Array
//   const encryptedArrayBuffer = new ArrayBuffer(encryptedBinaryString.length);
//   const encryptedUint8Array = new Uint8Array(encryptedArrayBuffer);
//   for (let i = 0; i < encryptedBinaryString.length; i++) {
//     encryptedUint8Array[i] = encryptedBinaryString.charCodeAt(i);
//   }

//   return encryptedUint8Array;
// }


function readRsaKeyFromPem(publicKeyPem: string): forge.pki.rsa.PublicKey {
  const pemObject = forge.pki.publicKeyFromPem(publicKeyPem);
  return pemObject;
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
 * Decodes a Uint8Array to a string.
 *
 * @param {Uint8Array} uint8Array - The Uint8Array to decode.
 * @returns {string} - The decoded string.
 */
const decodeUint8ArrayToString = (uint8Array: Uint8Array): string => {
  // Use TextDecoder to decode the Uint8Array to a string
  return new TextDecoder().decode(uint8Array);
};
/**
 * Converts a Base64 string to a Uint8Array.
 *
 * @param {string} base64 - The Base64 string to convert.
 * @returns {Uint8Array} - The resulting Uint8Array.
 */
const base64ToUint8Array = (base64: string): Uint8Array => {
  const binaryString = window.atob(base64);
  const length = binaryString.length;
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    // Convert each character in the binary string to its Unicode character code
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
};
/**
 * Splits an encrypted data string into its constituent parts and decodes them to Uint8Arrays.
 *
 * @param {string} encryptedDataStr - The encrypted data string to split.
 * @returns {Object} - An object containing the decoded Uint8Arrays for aesIv, encryptedAesData, and encryptedAesKey.
 */
const splitEncryptedData = (encryptedDataStr: string): { aesIv: Uint8Array; encryptedAesData: Uint8Array; encryptedAesKey: Uint8Array } => {

  // Find the boundaries for splitting the encrypted data string
  const aesIvEndIndex = 24; // Base64 encoded 16 bytes
  const encryptedAesKeyStartIndex = encryptedDataStr.length - 344; // Base64 encoded 256 bytes
  const encryptedAesKeyEndIndex = encryptedDataStr.length;

  // Extract Base64 strings for each part
  const aesIvBase64 = encryptedDataStr.substring(0, aesIvEndIndex);
  const encryptedAesKeyBase64 = encryptedDataStr.substring(encryptedAesKeyStartIndex, encryptedAesKeyEndIndex);
  const encryptedAesDataBase64 = encryptedDataStr.substring(aesIvEndIndex, encryptedAesKeyStartIndex);

  // Decode Base64 strings to Uint8Arrays
  const aesIv = base64ToUint8Array(aesIvBase64);
  const encryptedAesData = base64ToUint8Array(encryptedAesDataBase64);
  const encryptedAesKey = base64ToUint8Array(encryptedAesKeyBase64);

  return { aesIv, encryptedAesData, encryptedAesKey };
};



// function concatenateUint8Arrays1(iv: Uint8Array, encryptedData: Uint8Array, encryptedAesKey: Uint8Array): Uint8Array {
//   // Calculate the total length of all three Uint8Arrays
//   const totalLength = iv.length + encryptedData.length + encryptedAesKey.length;

//   // Create a new Uint8Array with the total length
//   const result = new Uint8Array(totalLength);

//   // Set each iv in the result at the correct offsets
//   result.set(iv, 0);
//   result.set(encryptedData, iv.length);
//   result.set(encryptedAesKey, iv.length + encryptedData.length);

//   return result;
// }

// function concatenateUint8Arrays(arrays: Uint8Array[]): Uint8Array {
//   // Calculate total length
//   const totalLength = arrays.reduce((acc, array) => acc + array.length, 0);

//   // Create new Uint8Array
//   const result = new Uint8Array(totalLength);

//   // Copy arrays into result
//   let offset = 0;
//   for (const array of arrays) {
//     result.set(array, offset);
//     offset += array.length;
//   }

//   return result;
// }
async function concatenateUint8ArraysAndEncodeBase64(arrays: Uint8Array[]): Promise<string> {
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



// function concatenateUint8Arrays(arrays: Uint8Array[]): Uint8Array {
//   const totalLength = arrays.reduce((acc, curr) => acc + curr.length, 0);
//   const result = new Uint8Array(totalLength);
//   let offset = 0;
//   arrays.forEach((array) => {
//     result.set(array, offset);
//     offset += array.length;
//   });
//   return result;
// }