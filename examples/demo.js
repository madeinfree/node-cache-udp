const NCUC = require('../client/node')

async function run() {
  const client = await new NCUC({
    timeout: 500,
  }).createClient()
  await client.ping()
  await client.set('CACHE', 'SWAP')
  const s = await client.get('CACHE')
  console.log(s)
  await client.del('CACHE')
  const ss = await client.get('CACHE')
  console.log(ss)
  await client.set('CACHE', 'SWAP2')
  const sss = await client.get('CACHE')
  console.log(sss)
  client.close()
}

run()
