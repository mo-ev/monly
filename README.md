# 🧬 monly 🔬
[![GitHub release](https://img.shields.io/github/release/mo-ev/monly.svg)](https://GitHub.com/mo-ev/monly/releases/) 
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/mo-ev/monly/graphs/commit-activity) 
[![GitHub forks](https://img.shields.io/github/forks/mo-ev/monly.svg?style=social&label=Fork&maxAge=2592000)](https://GitHub.com/mo-ev/monly/network/)
[![GitHub stars](https://img.shields.io/github/stars/mo-ev/monly.svg?style=social&label=Star&maxAge=2592000)](https://GitHub.com/mo-ev/monly/stargazers/)

[![GitHub issues](https://img.shields.io/github/issues/mo-ev/monly.svg)](https://GitHub.com/mo-ev/monly/issues/) 
[![GitHub issues-closed](https://img.shields.io/github/issues-closed/mo-ev/monly.svg)](https://GitHub.com/mo-ev/monly/issues?q=is%3Aissue+is%3Aclosed)

## Requirements 📌
- Docker `>= 19.03.0`
- NodeJS `>= 8.9.0`
- NPM `>= 5.6.0`
- Yarn `>= 1.6.0`

## Install 🧰
### Web Client Applikation

```bash
yarn install
```

Installs following dependencies:

- Quasar
- Axios
- Prisma
- Vue
- Vue-Router
- Vuex


### Web Server Applikation
```bash
cd server
yarn install
```

Installs following dependencies:

- frida
- frida-compile
- frida-screenshot
- koa
- koa-bodyparser
- koa-router
- koa2-cors

### Database Server Applikation 
```bash
docker-compose build
```

## Usage 🔦
### Web Client Applikation
Start the app in development mode (hot-code reloading, error reporting, etc.)

```bash
yarn web
```

- *App*: http://localhost:8080

Customize the app configuration
See [Configuring quasar.conf.js](https://quasar.dev/quasar-cli/quasar-conf-js).

### Web Server Applikation
Start the server in development mode (hot-code reloading, error reporting, etc.)

```bash
cd server
yarn dev
```

- *Server*: http://localhost:3000

### Database Server Applikation 
Start the docker dependencies

```bash
docker-compose up
```

- *MongoDB*: http://localhost:27017/
- *Prisma*: http://localhost:4466/_admin


## Getting started 🚀

## Credits 🌻
<div>Icons made by <a href="https://www.freepik.com/" title="Freepik">Freepik</a> from <a href="https://www.flaticon.com/"                 title="Flaticon">www.flaticon.com</a> is licensed by <a href="http://creativecommons.org/licenses/by/3.0/"                 title="Creative Commons BY 3.0" target="_blank">CC 3.0 BY</a></div>

## License 🔸
[![GitHub license](https://img.shields.io/github/license/mo-ev/monly.svg)](https://github.com/mo-ev/monly/blob/master/LICENSE)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/mo-ev/monly/blob/master/LICENSE/)
