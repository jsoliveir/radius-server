import QrCodeGenetator from './controllers/QrCodeGenerator.js';
import { default as axios } from 'axios';
import cookieParser from 'cookie-parser';
import querystring from 'querystring';
import { fileURLToPath } from 'url';
import express from 'express';
import path from 'path'

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
app.use('/', express.static(path.join(__dirname, '/public/app')))
app.use(cookieParser());
const port = 8080;

const clientId = process.env.AAD_CLIENT_ID
const tenantId = process.env.AAD_TENANT_ID
const redirectUri = 'http://localhost:8080/auth/callback'
const clientSecret = 'eyS8Q~OmmOUSL6_8j5GNkIMiLTtCzonO3RTMlb~E'
const scope = 'openid profile email';

const AUTHORITY = `https://login.microsoftonline.com/${process.env.AAD_TENANT_ID}`;

class AuthServer {

  constructor() {
    this.qrcode = new QrCodeGenetator(app)

    app.get('/login', this.authorize);
    app.get('/auth/callback', this.callback);
  }

  async start() {
    app.listen(port, () => {
      console.log(`Server listening on port ${port}`);
    })
  }

}


export default AuthServer