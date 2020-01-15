const nodemon = require('nodemon')
const compile = require('./lib/compile')

// start frida compiler
compile.run(true)

nodemon({
  script: 'app.js'
})
