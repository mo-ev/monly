export const monitor = async (axios, deviceId, appId) => {
  await axios.get('http://localhost:3000/api/monitor/' + deviceId + '/' + appId)
    .then((response) => {
      console.log(response.data)
    })
    .catch(() => {
      console.log('error')
    })
}

export const scans = async (axios, deviceId, appId) => {

}
