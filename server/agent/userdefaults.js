const { NSUserDefaults } = ObjC.classes

export function userDefaults() {
  return NSUserDefaults.alloc().init().dictionaryRepresentation()
}
