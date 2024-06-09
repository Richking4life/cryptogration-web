import React, { useEffect, useState } from 'react';
import { Button, Container, Grid, TextField, Typography } from '@mui/material';
import Logger from '../utils/logger'
import {
    decodeBase64ToUint8Array,
    encodeUint8ArrayToBase64,
    decryptPrivateKey,
    generateAndWrapRSAKeyPair,
    rsaDecryptor, rsaEncryptor,
    cryptoKeyToPem,
    generateRandomPassword
} from '../utils/encryption';

const RsaEncryptionComponent: React.FC = () => {
    const [publicKey, setPublicKey] = useState('');
    const [passphrase, setPassPhrase] = useState('');
    const [privateKey, setPrivateKey] = useState('');
    const [dataToEncrypt, setDataToEncrypt] = useState('');
    const [encryptedData, setEncryptedData] = useState('');
    const [decryptedData, setDecryptedData] = useState('');
    const [error, setError] = useState<string>('');
    const [passPhraseError, setPassPhraseError] = useState<string>('');

    useEffect(() => {

        if (passPhraseError)
            setPassPhraseError('');


    }, [passphrase, passPhraseError]);
    const handleGenerateKeys = async () => {
        try {
            // const _publicKey = '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt49eymH2PzNX7D9/iU2hX09GKKrE5wBBWE8psGf46+u6Ml48L8zPLlWGUAd4nRqf7YJs/M1OaAm7j02Nx3zJFxKmJqkSo3G7inv4CUI344FYAAyzsBHVMQzFGfVBpeDTw5BpbkbnOg/MgwkO5RV1oK4/Dryb6k1jwPhB/AuqGBxirfsDPgkY3irOQi0DJQMMcxurUYohkl8E3WP4ghZx4HKRym9v3hZ6CFI2l72f+69PdtyjzpU7vDpfc0uLrNX0uu1AIuEMFM1rC6qgIP+fns7F91vcJOzaHH1ZyJERJcXXP0mX81bmOmefS9tRGWyziE9jJKjIz3cyQwD8+0aH/QIDAQAB-----END PUBLIC KEY-----';

            setPassPhrase(generateRandomPassword(50))
            const pair = await generateAndWrapRSAKeyPair(passphrase);
            const privatekey = await cryptoKeyToPem(await decryptPrivateKey(pair.wrappedPrivateKey, passphrase, pair.salt, pair.iv));

            // const _publicKey = '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt49eymH2PzNX7D9/iU2hX09GKKrE5wBBWE8psGf46+u6Ml48L8zPLlWGUAd4nRqf7YJs/M1OaAm7j02Nx3zJFxKmJqkSo3G7inv4CUI344FYAAyzsBHVMQzFGfVBpeDTw5BpbkbnOg/MgwkO5RV1oK4/Dryb6k1jwPhB/AuqGBxirfsDPgkY3irOQi0DJQMMcxurUYohkl8E3WP4ghZx4HKRym9v3hZ6CFI2l72f+69PdtyjzpU7vDpfc0uLrNX0uu1AIuEMFM1rC6qgIP+fns7F91vcJOzaHH1ZyJERJcXXP0mX81bmOmefS9tRGWyziE9jJKjIz3cyQwD8+0aH/QIDAQAB-----END PUBLIC KEY-----';
            setPublicKey('-----BEGIN PUBLIC KEY-----' + pair.publicKey + '-----END PUBLIC KEY-----');
            setPrivateKey('-----BEGIN ENCRYPTED PRIVATE KEY-----' + privatekey + '-----END ENCRYPTED PRIVATE KEY-----');
            setError('');
        } catch (error) {
            Logger.error('Error generating keys:' + error);
            setError('An error occurred while generating keys.');
        }
    };

    const handleEncrypt = async () => {
        if (!publicKey || !privateKey) {
            setError('Please generate public and private keys before encrypting or decrypting data.');
            return;
        }

        if (!dataToEncrypt || !dataToEncrypt.trim()) {
            setError('Data to encrypt cannot be empty or contain only whitespace.');
            return;
        }

        setError('');

        try {
            const result = await rsaEncryptor(dataToEncrypt, publicKey);
            setEncryptedData(encodeUint8ArrayToBase64(result))
        } catch (error) {
            Logger.error('Error encrypting data:' + error);
            setError('An error occurred while encrypting the data.');
        }
    };

    const handleDecrypt = async () => {
        if (!publicKey || !privateKey) {
            setError('Please generate public and private keys before encrypting or decrypting data.');
            return;
        }
        try {
            const decryptedData = await rsaDecryptor(decodeBase64ToUint8Array(encryptedData), privateKey);
            setDecryptedData(decryptedData);

        } catch (error) {
            console.error('Error decrypting data:', error);
            setError('An error occurred while decrypting the data.');
        }
    };


    return (
        <Container maxWidth="md" style={{ marginTop: 40 }}>
            <Grid container spacing={3}>
                <Grid item xs={12}>
                    <Typography variant="h4" gutterBottom>
                        RSA Encryption & Decryption
                    </Typography>
                </Grid>
                <Grid item xs={6}>

                    <TextField
                        label="private passphrase"
                        value={passphrase}
                        fullWidth
                        onChange={(e) => setPassPhrase(e.target.value)}
                        multiline
                        rows={1}
                        disabled
                        error={Boolean(passPhraseError)}
                        helperText={passPhraseError}
                        variant="outlined"
                        style={{ marginTop: 1 }}

                    />
                    <TextField
                        label="Public Key"
                        value={publicKey}
                        fullWidth
                        multiline
                        rows={5}
                        variant="outlined"
                        style={{ marginTop: 20 }}
                        disabled
                    />
                </Grid>
                <Grid item xs={6}>

                    <TextField
                        label="Private Key"
                        value={privateKey}
                        fullWidth
                        multiline
                        rows={5}
                        variant="outlined"
                        disabled
                    />


                    <Button variant="contained" onClick={handleGenerateKeys} fullWidth>
                        Generate Keys
                    </Button>

                </Grid>
                <Grid item xs={12}>

                </Grid>
                <Grid item xs={6}>
                    <TextField
                        label="Data to Encrypt"
                        value={dataToEncrypt}
                        onChange={(e) => setDataToEncrypt(e.target.value)}
                        fullWidth
                        multiline
                        rows={5}
                        required
                        variant="outlined"
                        style={{ marginTop: 20 }}
                        error={Boolean(error)}
                        helperText={error}
                        autoFocus
                    />
                    <Button variant="contained" onClick={handleEncrypt} fullWidth style={{ marginTop: 20 }}>
                        Encrypt
                    </Button>
                    <TextField
                        label="Encrypted Data"
                        value={encryptedData}
                        fullWidth
                        multiline
                        rows={5}
                        variant="outlined"
                        style={{ marginTop: 20 }}
                        disabled
                    />
                </Grid>
                <Grid item xs={6}>


                    <TextField
                        label="Decrypted Data"
                        value={decryptedData}
                        fullWidth
                        multiline
                        rows={5}
                        required
                        variant="outlined"
                        disabled
                    />

                    <Button variant="contained" onClick={handleDecrypt} fullWidth>
                        Decrypt
                    </Button>
                </Grid>
            </Grid>
        </Container>
    );
};


export default RsaEncryptionComponent;
