const screenshot = require('frida-screenshot')

export default async function takeScreenshot () {
  const png = await screenshot()
  return png.base64EncodedStringWithOptions_(0).toString()
}
