import { date } from 'quasar'

export const formatDate = (val, format) => {
  if (date.isValid(val)) {
    return date.formatDate(new Date(val), format)
  } else {
    return val
  }
}
