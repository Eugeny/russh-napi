import * as russh from './native'
import { AsyncSubject, Subject } from "rxjs"

export class ClientEventInterface {
    data$ = new Subject<[number, Uint8Array]>()
    extendedData$ = new Subject<[number, number, Uint8Array]>()
    eof$ = new Subject<number>()
    close$ = new Subject<number>()
    disconnect$ = new Subject<void>()
    x11ChannelOpen$ = new Subject<[russh.SshChannel, string, number]>()
    tcpChannelOpen$ = new Subject<[russh.SshChannel, string, number, string, number]>()
    agentChannelOpen$ = new Subject<[russh.SshChannel]>()
    banner$ = new AsyncSubject<string>()

    complete () {
        this.data$.complete()
        this.extendedData$.complete()
        this.eof$.complete()
        this.close$.complete()
        this.disconnect$.complete()
        this.x11ChannelOpen$.complete()
        this.tcpChannelOpen$.complete()
        this.agentChannelOpen$.complete()
        this.banner$.complete()
    }

    dataCallback = (_: unknown, channel: number, data: Uint8Array) => {
        this.data$.next([channel, data])
    }

    extendedDataCallback = (_: unknown, channel: number, ext: number, data: Uint8Array) => {
        this.extendedData$.next([channel, ext, data])
    }

    eofCallback = (_: unknown, channel: number) => {
        this.eof$.next(channel)
    }

    closeCallback = (_: unknown, channel: number) => {
        this.close$.next(channel)
    }

    disconnectCallback = () => {
        this.disconnect$.next()
    }

    x11ChannelOpenCallback = (_: unknown, channel: russh.SshChannel, address: string, port: number) => {
        this.x11ChannelOpen$.next([channel, address, port])
    }

    tcpChannelOpenCallback = (_: unknown, channel: russh.SshChannel, connectedAddress: string, connectedPort: number, originatorAddress: string, originatorPort: number) => {
        this.tcpChannelOpen$.next([channel, connectedAddress, connectedPort, originatorAddress, originatorPort])
    }

    agentChannelOpenCallback = (_: unknown, channel: russh.SshChannel) => {
        this.agentChannelOpen$.next([channel])
    }

    bannerCallback = (_: unknown, banner: string) => {
        this.banner$.next(banner)
        this.banner$.complete()
    }
}
