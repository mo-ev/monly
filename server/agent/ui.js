const ui = require('frida-uikit');

const username = await ui.get(node => node.type === 'UITextField');
username.setText('john.doe');
