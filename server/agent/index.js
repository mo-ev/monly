import {appInfo} from './general'
import {observe, ssl} from './observe'
import {getOwnClasses} from './classes'
import {modules, imports, exports} from './modules'
import {dumpModule } from './binary'
import {cookies} from './cookies'
import {list} from '../keychain'
import {userDefaults} from './userdefaults'

rpc.exports = {
  appInfo,
  getOwnClasses,
  modules,
  imports,
  exports,
  dumpModule,
  cookies,
  list,
  userDefaults,
  ssl,
  observe
}
