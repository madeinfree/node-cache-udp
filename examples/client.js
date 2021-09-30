const NCUC = require('./nodeclient')

async function run() {
  const client = await new NCUC({
    timeout: 80,
  }).createClient()
  await client.set('CACHE', 'SWAP')
  const s = await client.get('CACHE')
  console.log(s)
  await client.del('CACHE')
  const ss = await client.get('CACHE')
  console.log(ss)
  await client.set('CACHE', 'SWAP2')
  const sss = await client.get('CACHE')
  console.log(sss)
}

run()
