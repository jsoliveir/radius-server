const {config}  = require("dotenv"); config();
const axios = require('axios').default;
const radius = require('radius');
const dgram = require("dgram");

const secret = process.env.RADIUS_SECRET
const clientId = process.env.AAD_CLIENT_ID
const tenantId = process.env.AAD_TENANT_ID
const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/token`;
const resource = 'https://graph.microsoft.com'
const server = dgram.createSocket("udp4");

server.on("message", async function (msg, rinfo) {
  var code, username, password, packet;
  packet = radius.decode({ packet: msg, secret: secret });

  if (packet.code != 'Access-Request') {
    console.log('unknown packet type: ', packet.code);
    return;
  }
  username = packet.attributes['User-Name'];
  password = packet.attributes['User-Password'];
  console.log('Access-Request for ' + username);

  const params = new URLSearchParams();
  params.append('grant_type', 'password');
  params.append('username', username);
  params.append('password', password);
  params.append('client_id', clientId);
  params.append('resource', resource);

  let authentication = 'Access-Reject';

  await axios.post(tokenEndpoint, params, {
    'Content-Type': 'application/x-www-form-urlencoded',
  })
    .then(response => {
      authentication = 'Access-Accept';
    })
    .catch(error => {
      if (error.response.data.error == 'interaction_required') {
        authentication = 'Access-Accept';
      }else{
        console.error(error.response.data.error_description)
      }
    });

  var response = radius.encode_response({
    code: authentication,
    packet: packet,
    secret: secret
  });

  console.log('Sending ' + authentication + ' for user ' + username);
  server.send(response, 0, response.length, rinfo.port, rinfo.address, function (err, bytes) {
    if (err) {
      console.log('Error sending response to ', rinfo);
    }
  });
});

server.on("listening", function () {
  var address = server.address();
  console.log("radius server listening " +
    address.address + ":" + address.port);
});

server.bind(process.env.PORT || 1812);