/*
 * To observe a single class by name:
 *     observeClass('NSString');
 *
 * To dynamically resolve methods to observe (see ApiResolver):
 *     observeSomething('*[* *Password:*]');
 */
var ISA_MASK = ptr('0x0000000ffffffff8');
var ISA_MAGIC_MASK = ptr('0x000003f000000001');
var ISA_MAGIC_VALUE = ptr('0x000001a000000001');

export const observePattern = (pattern, isArgs, isReturnValue, isBacktrace) => {
  var resolver = new ApiResolver('objc');
  var things = resolver.enumerateMatchesSync(pattern);
  things.forEach(function(thing) {
    observeMethod(thing.address, pattern, thing.name, isArgs, isReturnValue, isBacktrace);
  });

  return things
}

export const observeMethod = (impl, name, m, isArgs, isReturnValue, isBacktrace) => {
  Interceptor.attach(impl, {
    onEnter: function(args) {
      this.item = {}
      this.item['position'] = args[0]
      this.item['name'] = name
      this.item['method'] = m
      if (isArgs) {
        this.item['params'] = []
        if (m.indexOf(':') !== -1) {
          var params = m.split(':');
          params[0] = params[0].split(' ')[1];
          for (var i = 0; i < params.length - 1; i++) {
            if (isObjC(args[2 + i])) {
              const theObj = new ObjC.Object(args[2 + i]);
              this.item['params'].push(params[i] + ': ' + theObj.toString() + ' (' + theObj.$className + ')');
            } else {
              this.item['params'].push(params[i] + ': ' + args[2 + i].toString());
            }
          }
        }
      }

      if (isBacktrace) {
        this.item['backtrace'] = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
      }
    },

    onLeave: function(r) {

      if (isReturnValue) {
        if (isObjC(r)) {
          this.item['ret'] = 'RET: ' + new ObjC.Object(r).toString();
        } else {
          this.item['ret'] = 'RET: ' + r.toString();
        }
      }

      send(this.item);
    }
  });
}

const isObjC = (p) => {
  var klass = getObjCClassPtr(p);
  return !klass.isNull();
}

const getObjCClassPtr = (p) => {
  /*
   * Loosely based on:
   * https://blog.timac.org/2016/1124-testing-if-an-arbitrary-pointer-is-a-valid-objective-c-object/
   */

  if (!isReadable(p)) {
    return NULL;
  }
  var isa = p.readPointer();
  var classP = isa;
  if (classP.and(ISA_MAGIC_MASK).equals(ISA_MAGIC_VALUE)) {
    classP = isa.and(ISA_MASK);
  }
  if (isReadable(classP)) {
    return classP;
  }
  return NULL;
}

const isReadable = (p) => {
  try {
    p.readU8();
    return true;
  } catch (e) {
    return false;
  }
}
