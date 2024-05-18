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
export const decryptAesKey = async (encryptedAesKey: string, privateKey: string, keyFormat: 'pkcs8' | 'raw' = 'pkcs8'): Promise<string> => {
  const key = await crypto.subtle.importKey(keyFormat, decodeBase64ToUint8Array(privateKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const decryptedBuffer = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, decodeBase64ToUint8Array(encryptedAesKey));
  return new TextDecoder().decode(decryptedBuffer);
};

/**
 * Decrypts data using AES decryption.
 * @param encryptedData The encrypted data to be decrypted.
 * @param aesKey The AES key used for decryption.
 * @param iv The initialization vector (IV) used for encryption.
 * @returns The decrypted data.
 */
export const decryptData = async (encryptedData: string, aesKey: string, iv: string): Promise<string> => {
  const algorithm = { name: 'AES-CBC', iv: decodeBase64ToUint8Array(iv) };
  const key = await crypto.subtle.importKey('raw', decodeBase64ToUint8Array(aesKey), algorithm, false, ['decrypt']);
  const decryptedBuffer = await crypto.subtle.decrypt(algorithm, key, decodeBase64ToUint8Array(encryptedData));
  return new TextDecoder().decode(decryptedBuffer);
};



/**
 * Helper function to decode Base64 to Uint8Array.
 * @param base64String The Base64 string to be decoded.
 * @returns Uint8Array.
 */
const decodeBase64ToUint8Array = (base64String: string): Uint8Array => {
  return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
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
export const encryptWithRSA = async (data: string, publicKey: string) => {
  // Generate AES key
  const aesKey = generateAesKey();

  // Encrypt data using AES
  const { encryptedData, iv } = await encryptData(data, aesKey);

  // Encrypt AES key using RSA
  const encryptedAesKey = await encryptAesKey(aesKey, publicKey);

  return { encryptedData, iv, encryptedAesKey };
};

/**
 * Decrypts the provided data using AES decryption and the provided AES key decrypted using RSA decryption.
 * @param encryptedData The encrypted data to be decrypted.
 * @param iv The initialization vector (IV) used for encryption.
 * @param encryptedAesKey The encrypted AES key.
 * @param privateKey The RSA private key used for decrypting the AES key.
 * @returns The decrypted data.
 */
export const decryptWithRSA = async (encryptedData: string, iv: string, encryptedAesKey: string, privateKey: string) => {
  // Decrypt AES key using RSA
  const aesKey = await decryptAesKey(encryptedAesKey, privateKey);

  // Decrypt data using AES
  const decryptedData = await decryptData(encryptedData, aesKey, iv);

  return decryptedData;
};

/**
 * Helper function to encode Uint8Array to Base64.
 * @param array The Uint8Array to be encoded.
 * @returns Base64-encoded string.
 */
const encodeUint8ArrayToBase64 = (array: Uint8Array): string => {
  return btoa(String.fromCharCode.apply(null, Array.from(array)));
};