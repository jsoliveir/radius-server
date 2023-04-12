const { config } = require("dotenv"); config();
const axios = require('axios').default;
const radius = require('radius');
const dgram = require("dgram");
const server = dgram.createSocket("udp4");
const clientId = process.env.AAD_CLIENT_ID
const tenantId = process.env.AAD_TENANT_ID
const secret = process.env.RADIUS_SECRET

async function azureLogin(username, password) {
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

async function onMessageReceived(msg, rinfo) {
  //parse udp packet
  let packet = radius.decode({
    secret: secret,
    packet: msg
  });

  //log request
  if (packet.code != 'Access-Request') {
    console.log('unknown packet type: ', packet.code);
    return;
  }

  //parse username and password from the binary packet
  let username = packet.attributes['User-Name'];
  let password = packet.attributes['User-Password'];
  console.log(`Access-Request for ${username}`);

  //check credentials
  let authentication = await azureLogin(username, password)
    ? 'Access-Accept'
    : 'Access-Reject';

  //create the response packet
  var response = radius.encode_response({
    code: authentication,
    packet: packet,
    secret: secret
  });

  //send response
  console.log(`Sending ${authentication} for user ${username}`);
  server.send(response, 0, response.length, rinfo.port, rinfo.address, function (err, bytes) {
    if (err) {
      console.log('Error sending response to ', rinfo);
    }
  });
}

server.on("message", onMessageReceived);

server.on("listening", function () {
  var address = server.address();
  console.log(`radius server listening ${address.address}:${address.port}`);
});

server.bind(process.env.PORT || 1812);