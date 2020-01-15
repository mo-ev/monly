const compiler = require('frida-compile')

const tasks = [{
  src: 'agent/index.js',
  dest: 'agent.js'
}]

exports.run = function (watch) {
  const opt = {
    bytecode: false,
    compress: false,
    babelify: true,
    sourcemap: watch,
    typeroots: true,
    useAbsolutePaths: false
  }

  if (watch) {
    tasks.forEach(task => compiler.watch(task.src, task.dest, opt)
      .on('compile', (details) => {
        const count = details.files.length
        const { duration } = details
        console.log(`compiled ${count} file(s) in ${duration} ms`)
      }))
  } else {
    Promise
      .all(tasks.map(task => compiler.build(task.src, task.dest, opt)))
      .catch(err => console.error(err))
  }
}
