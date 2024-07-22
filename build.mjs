import { spawn, spawnSync } from 'child_process'

let targetTriple = process.env.RUST_TARGET_TRIPLE || {
    win32: {
        x64: 'x86_64-pc-windows-msvc',
        arm: 'arm-pc-windows-msvc',
        arm64: 'aarch64-pc-windows-msvc'
    },
    darwin: {
        x64: 'x86_64-apple-darwin',
        arm64: 'aarch64-apple-darwin'
    },
    linux: {
        x64: 'x86_64-unknown-linux-gnu',
        arm: 'armv7-unknown-linux-gnueabihf',
        arm64: 'aarch64-unknown-linux-musl'
    }
}[process.platform][process.arch]

console.log('Building for target triple', targetTriple, 'with args', process.argv.slice(2))
let cmd = ['napi', 'build', '--dts', 'russh.d.ts', '--target', targetTriple, '--platform', ...process.argv.slice(2)]
let p = spawnSync('npx', cmd, { stdio: 'inherit' })
console.log(p)
