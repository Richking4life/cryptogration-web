import React, { useEffect, useState } from 'react';
import { Button, Container, Grid, TextField, Typography } from '@mui/material';
import { generateRSAKeyPair, encryptWithRSA, decryptWithRSA } from '../utils/encryption';

const EncryptionForm: React.FC = () => {
    //const [iv, setIV] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const [privateKey, setPrivateKey] = useState('');
    //const [encryptedAesKey, setEncryptedAesKey] = useState('');
    const [dataToEncrypt, setDataToEncrypt] = useState('');
    const [encryptedData, setEncryptedData] = useState('');
    const [decryptedData, setDecryptedData] = useState('');
    const [error, setError] = useState<string>('');

    useEffect(() => {
        if (!publicKey || !privateKey) {
            setError('Please generate public and private keys before encrypting or decrypting data.');
        } else {
            setError('');
        }
    }, [publicKey, privateKey]);

    const handleGenerateKeys = async () => {
        try {
            const { publicKey, privateKey } = await generateRSAKeyPair();
            setPublicKey(publicKey);
            setPrivateKey(privateKey);
            setError('');
        } catch (error) {
            console.error('Error generating keys:', error);
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
            const result = await encryptWithRSA(dataToEncrypt, publicKey);
            //setConbinationData(result)
            setEncryptedData(result)
        } catch (error) {
            console.error('Error encrypting data:', error);
            setError('An error occurred while encrypting the data.');
        }
    };

    const handleDecrypt = async () => {
        if (!publicKey || !privateKey) {
            setError('Please generate public and private keys before encrypting or decrypting data.');
            return;
        }

        try {
            const decryptedData = await decryptWithRSA(encryptedData, privateKey);
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
                    <Button variant="contained" onClick={handleGenerateKeys} fullWidth>
                        Generate Keys
                    </Button>
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
                <Grid item xs={12}>
                    <Typography variant="h6" gutterBottom>
                        RSA Private Key
                    </Typography>
                    <TextField
                        label="Private Key"
                        value={privateKey}
                        fullWidth
                        multiline
                        rows={5}
                        variant="outlined"
                        disabled
                    />
                </Grid>
                <Grid item xs={6}>
                    <Button variant="contained" onClick={handleDecrypt} fullWidth>
                        Decrypt
                    </Button>
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
                </Grid>
            </Grid>
        </Container>
    );
};

export default EncryptionForm;
