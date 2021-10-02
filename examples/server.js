const fs = require('fs')
const NodeCacheUDP = require('../build').default

const server = new NodeCacheUDP({
  ca: fs.readFileSync('./keys/CA/cert.pem'),
  key: fs.readFileSync('./keys/CA/key.pem'),
})
server.createServer()
server.bind()
