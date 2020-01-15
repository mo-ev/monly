const http = require('http')

const frida = require('frida')
const FRIDA_VERSION = require('frida/package.json').version

const Koa = require('koa')
const compress = require('koa-compress')
const bodyParser = require('koa-bodyparser')
const Router = require('koa-router')
const cors = require('koa2-cors')

const fs = require('fs')

const config = require('./config.json')

const { FridaUtil, serializeDevice, serializeApp } = require('./lib/utils')
const {
  KnownError,
  InvalidDeviceError,
  VersionMismatchError
} = require('./lib/error')

const { prisma } = require('../prisma/generated/prisma-client')

const api = new Koa()
api.use(cors())
const router = new Router({ prefix: '/api' })

let session, scan, script, observeItems

async function spawn (deviceId, appId) {
  const dev = await FridaUtil.getDevice(deviceId)
  const apps = await dev.enumerateApplications()
  const app = apps.find(item => item.identifier === appId)
  if (!app) throw new Error('app not installed')

  if (app.pid) {
    const front = await dev.getFrontmostApplication()
    if (front && front.pid === app.pid) {
      session = await dev.attach(app.pid)
    } else {
      await dev.kill(app.pid)
      session = await FridaUtil.spawn(dev, app)
    }
  } else {
    session = await FridaUtil.spawn(dev, app)
  }
}

async function monitor (deviceId, appId, hooks, options) {
  await configure(deviceId, appId)
  scan = await prisma.createScan({
    app: appId,
    device: deviceId
  })

  let hookList = []
  hooks.forEach((item) => {
    hookList.push(item.hook)
  })

  const isArgs = options.includes('args')
  const isReturnValue = options.includes('returnValue')
  const isBacktrace = options.includes('backtrace')

  // eslint-disable-next-line no-return-await
  observeItems = await script.exports.observe(hookList, isArgs, isReturnValue, isBacktrace)
  return { 'scan': scan, 'items': observeItems }
}

async function general (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.appInfo()
}

async function modules (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.modules()
}

async function imports (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.imports()
}

async function exports (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.exports()
}

async function classes (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.getOwnClasses()
}

async function cookies (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.cookies()
}

async function keychain (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.list()
}

async function userDefaults (deviceId, appId) {
  await configure(deviceId, appId)
  return script.exports.userDefaults()
}

async function configure (deviceId, appId) {
  if (!session) {
    await spawn(deviceId, appId)
  }

  if (!script) {
    await session.enableJit()
    const source = fs.readFileSync('./agent.js')
    script = await session.createScript(source)
    script.message.connect(onMessage)
    await script.load()
  }
}

async function onMessage (message, data) {
  await prisma.createScanItem({
    data: message,
    scanId: scan.id
  })
}

router
  .get('/devices', async ctx => {
    const list = await frida.enumerateDevices()
    ctx.body = {
      version: FRIDA_VERSION,
      list: list.filter(FridaUtil.isUSB).map(serializeDevice)
    }
  })
  .get('/device/:deviceId/apps', async ctx => {
    const id = ctx.params.deviceId
    try {
      const dev = await FridaUtil.getDevice(id)
      const apps = await dev.enumerateApplications()
      ctx.body = apps.map(serializeApp)
    } catch (ex) {
      if (ex.message.startsWith('Unable to connect to remote frida-server')) { throw new InvalidDeviceError(id) }
      if (
        ex.message.startsWith('Unable to communicate with remote frida-server')
      ) { throw new VersionMismatchError(ex.message) } else throw ex
    }
  })
  .get('/device/:deviceId/:appId/info', async ctx => {
    const { deviceId, appId } = ctx.params
    const _general = await general(deviceId, appId)
    const _modules = await modules(deviceId, appId)
    const _imports = null // await imports(deviceId, appId)
    const _exports = null // await exports(deviceId, appId)
    const _classes = await classes(deviceId, appId)
    const _cookies = await cookies(deviceId, appId)
    const _keychain = await keychain(deviceId, appId)
    const _userDefaults = await userDefaults(deviceId, appId)
    ctx.body = { general: _general, modules: _modules, imports: _imports, exports: _exports, classes: _classes, storage: { keychain: _keychain, cookies: _cookies, userDefaults: _userDefaults } }
  })
  .post('/monitor/:deviceId/:appId', async ctx => {
    // monitor app from device with given hooks
    const { deviceId, appId } = ctx.params
    const body = ctx.request.body
    const result = await monitor(deviceId, appId, body.hooks, body.options)
    ctx.body = { result: result }
  })
  .get('/monitor/observed', async ctx => {
    ctx.body = { result: observeItems }
  })
  .get('/scans', async ctx => {
    // list of all scans
    const scans = await prisma.scans()
    ctx.body = { status: 'success', scans: scans }
  })
  .get('/scans/:id', async ctx => {
    // specific scan
    const { id } = ctx.params
    const scanItems = await prisma.scanItems({ where: { scanId: id } })
    ctx.body = { status: 'success', scanItems: scanItems }
  })
  .get('/state', async ctx => {
    console.log('session' + JSON.stringify(session))
    ctx.body = {
      session: session ? session.impl.pid : null
    }
  })
  .get('/state/reset/:deviceId', async ctx => {
    const { deviceId } = ctx.params

    await frida.kill(session.impl.pid)
    const dev = await FridaUtil.getDevice(deviceId)
    await dev.kill(session.impl.pid)
    session = null
    script = null
    ctx.body = {}
  })

api
  .use(
    compress({
      filter (contentType) {
        return /text|json/i.test(contentType)
      },
      threshold: 2048
    })
  )
  .use(bodyParser())
  .use(async (ctx, next) => {
    try {
      await next()
    } catch (e) {
      if (e instanceof KnownError) ctx.throw(404, e.message)

      if (process.env.NODE_ENV === 'development') throw e
      else ctx.throw(500, e.message)
    }
  })
  .use(router.routes())

const port = config.app.port
const host = config.app.host
api.listen(() => {
  console.log(`Server listening at port ${port}`)
  const server = http.createServer(api.callback())
  server.listen(port, host)
})
