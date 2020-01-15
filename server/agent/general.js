export const appInfo = () => {
  const { NSBundle, NSProcessInfo } = ObjC.classes

  var output = {};
  output["name"] = infoLookup("CFBundleName");
  output["bundleIdentifier"] = NSBundle.mainBundle().bundleIdentifier().toString();
  output["version"] = infoLookup("CFBundleVersion");
  output["bundle"] = NSBundle.mainBundle().bundlePath().toString();
  output["data"] = NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
  output["binary"] = NSBundle.mainBundle().executablePath().toString();

  return output;
};

const infoLookup = (key) => {
  if (ObjC.available && "NSBundle" in ObjC.classes) {
    var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    var value = info.objectForKey_(key);
    if (value === null) {
      return value;
    } else if (value.class().toString() === "__NSCFArray") {
      return arrayFromNSArray(value);
    } else if (value.class().toString() === "__NSCFDictionary") {
      return dictFromNSDictionary(value);
    } else {
      return value.toString();
    }
  }
  return null;
}
