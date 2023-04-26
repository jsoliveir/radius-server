import { config } from "dotenv"; config();
import { default as axios } from 'axios';
import radius from 'radius';
import dgram from "dgram";
const server = dgram.createSocket("udp4");
const clientId = process.env.AAD_CLIENT_ID
const tenantId = process.env.AAD_TENANT_ID
const secret = process.env.RADIUS_SECRET
import { authenticator } from 'otplib';
import objectHash from 'object-hash';
import { DefaultAzureCredential, ManagedIdentityCredential } from '@azure/identity'
import { Buffer } from 'buffer'
import { base32 } from 'rfc4648'

class RadiusServer {
  sessions = {}

  stop() { }

  async start() {

    server.on("message", this.onMessageReceived.bind(this));

    server.on("listening", (function () {
      var address = server.address();
      console.log(`radius server listening ${address.address}:${address.port}`);
    }).bind(this));

    await new Promise(() =>
      server.bind(process.env.PORT || 1812)
    )
  }

  async azureLogin(username, password) {
    if (!password)
      return false

    const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/token`;
    const resource = 'https://graph.microsoft.com'
    const params = new URLSearchParams();
    params.append('grant_type', 'password');
    params.append('username', username);
    params.append('password', password);
    params.append('client_id', clientId);
    params.append('resource', resource);

    // access denied by default
    let authenticated = false

    // check the user's credentials against AAD
    await axios.post(tokenEndpoint, params, { 'Content-Type': 'application/x-www-form-urlencoded' })
      .then(() => {
        authenticated = true
      })
      .catch(error => {
        // if the error is interaction_required means the logon could not be completed due to 2FA
        if (error.response.data.error == 'interaction_required') {
          // then ignore it
          authenticated = true
        } else {
          console.log(new Date().toJSON(), username, error.response.data)
        }
      });
    return authenticated
  }

  async verifyOtp(email, otp) {
    if (!otp)
      return false

    const credentials = process.env.ENVIRONMENT == "azure"
      ? new ManagedIdentityCredential()
      : new DefaultAzureCredential()

    const scopes = ["https://graph.microsoft.com/.default"]; // Replace with the scopes you need

    try {
      await new Promise((resolve, reject) => {
        credentials
          .getToken(scopes)
          .then((response) => {
            fetch(`https://graph.microsoft.com/v1.0/users/${email}?$select=securityIdentifier,lastPasswordChangeDateTime,accountEnabled`, {
              headers: {
                'Authorization': `Bearer ${response.token}`
              }
            })
              .then(response => response.json())
              .then(data => {
                const json = {
                  sid: data.securityIdentifier,
                  lpc: data.lastPasswordChangeDateTime,
                  ace: data.accountEnabled,
                  aid: process.env.AAD_CLIENT_ID
                }
                const secret = objectHash.sha1(json)
                const encoded = base32.stringify(Buffer.from(secret));
                authenticator.options = { ...authenticator.allOptions(), window: [2 * 60 * 24, 1] }
                const validOtp = authenticator.check(otp, encoded)
                if (validOtp) {
                  resolve()
                }
                else {
                  reject('invalid otp')
                }
              }).catch(err => {
                console.log(new Date().toJSON(), email, err)
                reject(err)
              })
          })
          .catch((error) => {
            console.log(new Date().toJSON(), email, error);
          });
      })
    } catch {
      return false
    }
    return true
  }

  async onMessageReceived(msg, rinfo) {
    //parse udp packet
    let packet = radius.decode({
      secret: secret,
      packet: msg
    });

    //log request
    if (packet.code != 'Access-Request') {
      console.log(new Date().toJSON(), 'unknown packet type: ', packet.code);
      return;
    }

    //parse username and password from the binary packet
    let username = packet.attributes['User-Name'];
    let password = packet.attributes['User-Password'].slice(6);
    let otp = packet.attributes['User-Password'].slice(0, 6);

    if (!this.sessions[username])
      this.sessions[username] = {}

    let session = this.sessions[username]

    session.validOtp = await this.verifyOtp(username, otp)

    session.authenticated =
      await this.azureLogin(username, password) ||
      await this.azureLogin(username, otp + password)

    console.log(new Date().toJSON(), username, session)

    let authentication =
      session.authenticated && session.validOtp
        ? 'Access-Accept'
        : 'Access-Reject';

    setTimeout(() => {
      //create the response packet
      var response = radius.encode_response({
        code: authentication,
        packet: packet,
        secret: secret
      });

      //send response
      console.log(new Date().toJSON(), username, authentication)
      server.send(response, 0, response.length, rinfo.port, rinfo.address, function (err, bytes) {
        if (err) {
          console.log(new Date().toJSON(), username, 'Error sending response', rinfo);
        }
      });
    }, 500 * session.attempts)

  }
}

export default RadiusServer