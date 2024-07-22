let _russh

const nativeModule = process.env.RUST_TARGET_TRIPLE || {
    win32: {
        x64: 'win32-x64-msvc',
        arm64: 'win32-arm64-msvc'
    },
    darwin: {
        x64: 'darwin-x64',
        arm64: 'darwin-arm64'
    },
    linux: {
        x64: 'linux-x64-gnu',
        arm: 'linux-arm-gnueabihf',
        arm64: 'linux-arm64-gnu'
    }
}[process.platform][process.arch]

// try {
_russh = require(`../russh.${nativeModule}.node`)
// } catch {
//     _russh = require('../russh.node')
// }

module.exports = _russh
