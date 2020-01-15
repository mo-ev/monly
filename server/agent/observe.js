import {observePattern} from './util/observe'
import {bypassSSL} from './util/ssl'

export const ssl = () => {
  bypassSSL()
}

export const observe = (hookList, isArgs, isReturnValue, isBacktrace) => {
  let observedItems = []
  hookList.forEach(hook => {
    const response = observePattern(hook)
    observedItems.push(response)
  })
  return observedItems
}
