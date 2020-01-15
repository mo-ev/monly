const frida = require('frida')
const { DeviceNotFoundError, AppNotFoundError } = require('./error')

class FridaUtil {
  static isUSB (dev) {
    return dev && ['tether', 'usb'].indexOf(dev.type) > -1
  }

  static async getDevice (id) {
    const list = await frida.enumerateDevices()
    const dev = list.find(d => d.id === id && FridaUtil.isUSB(d))

    if (dev) return dev
    throw new DeviceNotFoundError(id)
  }

  static async spawn (dev, app) {
    const pid = await dev.spawn([app.identifier])
    const session = await dev.attach(pid)

    if (session) return session
    throw new AppNotFoundError(dev, app)
  }
}

function serializeIcon (icon) {
  if (!icon) return icon
  const { pixels, height, width, rowstride } = icon
  return { width, height, rowstride, pixels: pixels.toString('base64') }
}

function serializeDevice (dev) {
  const { name, id, icon } = dev
  return { name, id, icon: serializeIcon(icon) }
}

function serializeApp (app) {
  const { name, id, smallIcon, largeIcon, identifier } = app
  return {
    name,
    id,
    identifier,
    smallIcon: serializeIcon(smallIcon),
    largeIcon: serializeIcon(largeIcon)
  }
}

function uuidv4 () {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : ((r & 0x3) | 0x8)
    return v.toString(16)
  })
}

module.exports = {
  FridaUtil,
  serializeDevice,
  serializeApp,
  uuidv4
}
