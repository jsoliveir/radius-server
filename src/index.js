import { config } from "dotenv"; config();
import Radius from './servers/radius.js'
import Auth from './servers/auth.js'


Promise.all([
    new Radius().start(),
    new Auth().start()
])
