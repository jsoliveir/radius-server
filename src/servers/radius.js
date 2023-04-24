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

  log(object) {
    console.log(new Date().toJSON(), object);
  }

  async start() {

    server.on("message", this.onMessageReceived.bind(this));

    server.on("listening", (function () {
      var address = server.address();
      this.log(`radius server listening ${address.address}:${address.port}`);
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
          console.error(error.response.data.error_description)
        }
      });
    return authenticated
  }

  async verifyOtp(email, otp) {
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
                const validOtp = authenticator.check(otp, encoded)
                if (validOtp) {
                  this.log(`${email} : valid otp`)
                  resolve()
                }
                else {
                  this.log(`${email} : invalid or expired otp`)
                  reject('invalid otp')
                }
              }).catch(err => {
                this.log(err)
                reject(err)
              })
          })
          .catch((error) => {
            this.log(error);
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
      this.log('unknown packet type: ', packet.code);
      return;
    }


    //parse username and password from the binary packet
    let username = packet.attributes['User-Name'];
    let password = packet.attributes['User-Password'].slice(6);
    let otp = packet.attributes['User-Password'].slice(0, 6);
    console.log(`${username}: Access-Request`)

    if (!this.sessions[username])
      this.sessions[username] = {}

    let session = this.sessions[username]

    if (!session.attempts || session.attempts > 2)
      session.attempts = 1
    else
      session.attempts++

    if (!session.hasValidOtp || session.address != rinfo.address || Math.abs(session.attempts % 2) == 1) {
      session.hasValidOtp = await this.verifyOtp(username, otp)
    }

    if (!session.isAuthenticated || session.address != rinfo.address || Math.abs(session.attempts % 2) == 0) {
      session.isAuthenticated =
        await this.azureLogin(username, password) ||
        await this.azureLogin(username, otp + password)
    }

    if (session.isAuthenticated || session.hasValidOtp) {
      session.address = rinfo.address
    }

    console.log(username, session)

    let authentication =
      rinfo.address === session.address
        && session.isAuthenticated
        && session.hasValidOtp
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
      this.log(`${username}: ${authentication}`)
      server.send(response, 0, response.length, rinfo.port, rinfo.address, function (err, bytes) {
        if (err) {
          this.log(`${username}:Error sending response`, rinfo);
        }
      });
    }, 500 * session.attempts)

  }
}

export default RadiusServer