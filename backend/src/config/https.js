import https from 'https';

// Used for local/internal API connections that might have self-signed certificates
export const httpsAgent = new https.Agent({ rejectUnauthorized: false });
