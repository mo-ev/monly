export function updateVersion (state, version) {
  state.fridaVersion = version
}

export function updateDevice (state, device) {
  if (device === null) {
    state.deviceName = null
    state.deviceId = null
  } else {
    state.deviceName = device.name
    state.deviceId = device.id
  }
}

export function updateApp (state, app) {
  if (app === null) {
    state.appId = null
    state.appName = null
  } else {
    state.appId = app.identifier
    state.appName = app.name
  }
}

export function updateSession (state, session) {
  state.session = session
}
