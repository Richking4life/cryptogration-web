import { useState } from 'react';
import { Button, Container, Grid, TextField, Typography } from '@mui/material';
import { generateRSAKeyPair, encryptWithRSA, decryptWithRSA } from '../utils/encryption'

const EncryptionForm: React.FC = () => {
    const [iv, setIV] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const [privateKey, setPrivateKey] = useState('');
    const [encryptedAesKey, setEncryptedAesKey] = useState('');
    const [dataToEncrypt, setDataToEncrypt] = useState('');
    const [encryptedData, setEncryptedData] = useState('');
    const [decryptedData, setDecryptedData] = useState('')


    const handleGenerateKeys = async () => {
        try {
            const { publicKey, privateKey } = await generateRSAKeyPair();
            setPublicKey(publicKey);
            setPrivateKey(privateKey);
        } catch (error) {
            console.error('Error generating keys:', error);
        }
    };

    const handleEncrypt = async () => {
        // Implement encryption logic using RSA public key
        // Update encryptedData state with the encrypted result

        const result = await encryptWithRSA(dataToEncrypt, publicKey);
        setEncryptedData(result.encryptedData);
        setIV(result.iv);
        setEncryptedAesKey(result.encryptedAesKey);
    };

    const handleDecrypt = async () => {
        // Implement decryption logic using RSA private key
        // Update decryptedData state with the decrypted result
        try {
            const decryptedData = await decryptWithRSA(encryptedData, iv, encryptedAesKey, privateKey);
            console.log('Decrypted Data:', decryptedData);
            setDecryptedData(decryptedData);

        } catch (error) {
            console.error('Error:', error);
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
                        variant="outlined"
                        style={{ marginTop: 20 }}
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
                        variant="outlined"
                        disabled
                    />
                </Grid>
            </Grid>
        </Container>
    );
};


export default EncryptionForm;
// EncryptionForm.tsx