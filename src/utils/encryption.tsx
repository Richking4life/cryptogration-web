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
 * Encrypts data using AES encryption.
 * @param data The data to be encrypted.
 * @param aesKey The AES key used for encryption.
 * @returns An object containing the encrypted data and the IV used for encryption.
 */
export const encryptData = async (data: string, aesKey: string): Promise<{ encryptedData: string; iv: string }> => {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encodedData = new TextEncoder().encode(data);
  const algorithm = { name: 'AES-CBC', iv };
  const key = await crypto.subtle.importKey('raw', decodeBase64ToUint8Array(aesKey), algorithm, false, ['encrypt']);
  const encryptedBuffer = await crypto.subtle.encrypt(algorithm, key, encodedData);
  return { encryptedData: encodeUint8ArrayToBase64(new Uint8Array(encryptedBuffer)), iv: encodeUint8ArrayToBase64(iv) };
};
/**
 * Encrypts an AES key using RSA encryption.
 * @param aesKey The AES key to be encrypted.
 * @param publicKey The RSA public key used for encryption.
 * @param keyFormat The format of the RSA public key (default: 'spki').
 * @returns Base64-encoded string representation of the encrypted AES key.
 */
export const encryptAesKey = async (aesKey: string, publicKey: string, keyFormat: 'spki' | 'raw' = 'spki'): Promise<string> => {
  const encodedKey = new TextEncoder().encode(aesKey);
  const key = await crypto.subtle.importKey(keyFormat, decodeBase64ToUint8Array(publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const encryptedBuffer = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, encodedKey);
  return encodeUint8ArrayToBase64(new Uint8Array(encryptedBuffer));
};

/**
 * Decrypts an AES key using RSA decryption.
 * @param encryptedAesKey The encrypted AES key to be decrypted.
 * @param privateKey The RSA private key used for decryption.
 * @param keyFormat The format of the RSA private key (default: 'pkcs8').
 * @returns The decrypted AES key.
 */
export const decryptAesKey = async (encryptedAesKey: Uint8Array, privateKey: string, keyFormat: 'pkcs8' | 'raw' = 'pkcs8'): Promise<string> => {
  const key = await crypto.subtle.importKey(keyFormat, decodeBase64ToUint8Array(privateKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const decryptedBuffer = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, encryptedAesKey);
  return new TextDecoder().decode(decryptedBuffer);
};

/**
 * Decrypts data using AES decryption.
 * @param encryptedData The encrypted data to be decrypted.
 * @param aesKey The AES key used for decryption.
 * @param iv The initialization vector (IV) used for encryption.
 * @returns The decrypted data.
 */
export const decryptData = async (encryptedData: Uint8Array, aesKey: string, iv: Uint8Array): Promise<string> => {
  const algorithm = { name: 'AES-CBC', iv: iv };
  const key = await crypto.subtle.importKey('raw', decodeBase64ToUint8Array(aesKey), algorithm, false, ['decrypt']);
  const decryptedBuffer = await crypto.subtle.decrypt(algorithm, key, encryptedData);
  return new TextDecoder().decode(decryptedBuffer);
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
 * Encrypts the provided data using AES encryption and encrypts the AES key using RSA encryption.
 * @param data The data to be encrypted.
 * @param publicKey The RSA public key used for encrypting the AES key.
 * @returns An object containing the encrypted data, the IV used for encryption, and the encrypted AES key.
 */
export const encryptWithAesAndRSA = async (data: string, publicKey: string) => {
  // Generate AES key
  const aesKey = generateAesKey();

  // Encrypt data using AES
  const { encryptedData, iv } = await encryptData(data, aesKey);

  // Encrypt AES key using RSA
  const encryptedAesKey = await encryptAesKey(aesKey, publicKey);

  // Usage example:
  // const combinedData = concatenateUint8Arrays([aesAlg.IV, encryptedAesData, encryptedAesKey]);
  // Usage example:
  return concatenateArraysToString([iv, encryptedData, encryptedAesKey]); //{ encryptedData, iv, encryptedAesKey };
};
/**
 * Decrypts the provided data using AES decryption and the provided AES key decrypted using RSA decryption.
 * @param encryptedData The encrypted data to be decrypted.
 * @param iv The initialization vector (IV) used for encryption.
 * @param encryptedAesKey The encrypted AES key.
 * @param privateKey The RSA private key used for decrypting the AES key.
 * @returns The decrypted data.
 */
export const decryptWithAesAndRSA = async (combinedData: string, privateKey: string): Promise<string> => {

  // Split combinedData into encryptedData, iv, and encryptedAesKey
  const result = splitEncryptedData(combinedData);

  // Decrypt AES key using RSA
  const aesKey = await decryptAesKey(result.encryptedAesKey, privateKey);

  // Decrypt data using AES
  const decryptedData = await decryptData(result.encryptedAesData, aesKey, result.aesIv);

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
/**
 * Helper function to encode Uint8Array to Base64.
 * @param array The Uint8Array to be encoded.x
 * @returns Base64-encoded string.
 */
const encodeUint8ArrayToBase64 = (array: Uint8Array): string => {
  const binaryString = Array.from(array).map(byte => String.fromCharCode(byte)).join('');
  return btoa(binaryString);
};
/**
 * Concatenates an array of Uint8Array and string elements into a single string.
 *
 * @param {Array<Uint8Array | string>} arrays - The input array containing Uint8Array and string elements.
 * @returns {string} - The concatenated string.
 */
const concatenateArraysToString = (arrays: (Uint8Array | string)[]): string => {
  const textDecoder = new TextDecoder(); // Create a TextDecoder instance once for efficiency

  return arrays.map(item =>
    // Check if the item is a string and return it directly, otherwise decode the Uint8Array
    typeof item === 'string' ? item : textDecoder.decode(item)
  ).join('');
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
