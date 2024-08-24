# N-API bindings for russh

This library contains neatly wrapped and typed native bindings for the client side of the [russh](https://github.com/warp-tech/russh) SSH protocol library.

Curently I'm only maintaining it as a dependency of [Tabby](https://github.com/eugeny/tabby) and not for general public use. However it is mostly stable, self-documented through type definitions and ready to use.

Run `yarn local:debug` to build a debug binding for your platform. GitHub CI builds bindings for all platforms and that's what gets published to npm.
