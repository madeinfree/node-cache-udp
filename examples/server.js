const NodeCacheUDP = require('../build').default

const server = new NodeCacheUDP()
server.createServer()
server.bind()
