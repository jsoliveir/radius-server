import { authenticator } from 'otplib';
import jwt from 'jsonwebtoken';
import crypto  from 'crypto';
import qrcode from 'qrcode';

class QrCodeGernerator {
  
  constructor(express){
    express.get('/api/qrcode', this.get);
  }

  async get(req, res) {
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
    res.send(data);
    res.end()
  }
}

export default QrCodeGernerator