import { config } from "dotenv"; config();
import RadiusServer from './servers/radius.js'


Promise.all([
    new RadiusServer().start(),
])

process.on('uncaughtException', function (err) {
  console.log('Caught exception: ' + err);
});