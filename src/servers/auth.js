import express from 'express';
import qrcode from 'qrcode';
import { authenticator } from 'otplib';
import querystring from 'querystring';
import { default as axios } from 'axios';
import cookieParser from 'cookie-parser';
import crypto  from 'crypto';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cookieParser());
const port = 8080;

const clientId = process.env.AAD_CLIENT_ID
const tenantId = process.env.AAD_TENANT_ID
const redirectUri = 'http://localhost:8080/auth/callback'
const clientSecret = 'eyS8Q~OmmOUSL6_8j5GNkIMiLTtCzonO3RTMlb~E'
const scope = 'openid profile email';

const AUTHORITY = `https://login.microsoftonline.com/${process.env.AAD_TENANT_ID}`;

class AuthServer {

  stop() { }

  async start() {
    app.get('/', this.authorize);

    app.get('/auth/callback', this.callback);

    app.get('/profile', this.getQRCode);

    app.listen(port, () => {
      console.log(`Server listening on port ${port}`);
    })
  }

  async authorize(req, res) {
    const authorizationEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`;
      const queryParams = querystring.stringify({
        client_id: clientId,
        response_type: 'code',
        redirect_uri: redirectUri,
        response_mode: 'query',
        scope: scope
      });
      const authorizationUrl = `${authorizationEndpoint}?${queryParams}`;
      res.redirect(authorizationUrl);
  }

  async callback(req, res) {
    const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
    const code = req.query.code;
    const data = {
      grant_type: 'authorization_code',
      client_id: clientId,
      code: code,
      redirect_uri: redirectUri,
      scope: scope,
      client_secret: clientSecret
    };
    await axios.post(tokenEndpoint, querystring.stringify(data), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }).then(async response => {
      res.cookie("token", response.data.access_token, { httpOnly: true })
      res.redirect(`/profile`);
    }).catch(error => console.error(error))
  }

  async getQRCode(req, res) {
    // Extract the secret from the query parameters
    const accessToken = req.cookies.token;

    const decodedToken = jwt.decode(accessToken);

    const tokenExpirationTime = decodedToken.exp;

    const currentTime = Math.floor(Date.now() / 1000);

    if (currentTime > tokenExpirationTime) {
      console.log('Token has expired.');
      res.redirect('/');
    } 

    // Use the access token to make requests to Azure AD Graph API
    const graphApiEndpoint = 'https://graph.microsoft.com/v1.0/me';
    const graphApiResponse = await axios.get(graphApiEndpoint, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    const userEmail = graphApiResponse.data.mail
    
    const secret = crypto.createHmac('sha256', clientSecret)
      .update(graphApiResponse.data.mail)
      .digest('hex');

    // For TOTP
    const url = authenticator.keyuri(userEmail, 'Habitus Health VPN', secret);
    const data = await qrcode.toDataURL(url, { width: 512 });
    res.send(`<img src="${data}"/>`);
    res.end()
  }
}


export default AuthServer