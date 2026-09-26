import * as russh from './native'
import { AsyncSubject, Observable, share, startWith, Subject } from "rxjs"

class ChannelSpecificEventBuffer<T> {
    #subject: Subject<T> | null = null
    #buffer: T[] = []

    next (item: T) {
        if (!this.#subject) {
            this.#buffer.push(item)
        } else {
            this.#subject.next(item)
        }
    }

    flush (): [T[], Observable<T>] {
        if (!this.#subject) {
            this.#subject = new Subject<T>()
        }
        try {
            return [this.#buffer, this.#subject.asObservable()]
        } finally {
            this.#buffer = []
        }
    }

    complete () {
        this.#subject?.complete()
    }
}

class ChannelEventBuffer<T = void> {
    #buffers: Map<number, ChannelSpecificEventBuffer<T>> = new Map()

    private getBuffer (channel: number): ChannelSpecificEventBuffer<T> {
        let buffer = this.#buffers.get(channel)
        if (!buffer) {
            buffer = new ChannelSpecificEventBuffer<T>()
            this.#buffers.set(channel, buffer)
        }
        return buffer
    }

    next (channel: number, item: T) {
        let buffer = this.getBuffer(channel)
        buffer.next(item)
    }

    subscribe (channel: number): Observable<T> {
        let buffer = this.getBuffer(channel)
        return new Observable<T>(subscriber => {
            const [data, subject] = buffer.flush()
            const subscription = subject.pipe(startWith(...data)).subscribe(subscriber)
            return () => {
                subscription.unsubscribe()
            }
        }).pipe(share())
    }

    closeChannel (channel: number) {
        this.#buffers.delete(channel)
    }

    complete () {
        for (const buffer of this.#buffers.values()) {
            buffer.complete()
        }
    }
}

/** How long a closed channel's events are still delivered to its subscribers. */
const LATE_EVENTS_GRACE_MS = 5000

export class ClientEventInterface {
    data$ = new ChannelEventBuffer<Uint8Array>()
    extendedData$ = new ChannelEventBuffer<[number, Uint8Array]>()
    eof$ = new ChannelEventBuffer()
    close$ = new ChannelEventBuffer()
    disconnect$ = new Subject<void>()
    x11ChannelOpen$ = new Subject<[russh.NewSshChannel, string, number]>()
    tcpChannelOpen$ = new Subject<[russh.NewSshChannel, string, number, string, number]>()
    agentChannelOpen$ = new Subject<[russh.NewSshChannel]>()
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
        this.data$.next(channel, data)
    }

    extendedDataCallback = (_: unknown, channel: number, ext: number, data: Uint8Array) => {
        this.extendedData$.next(channel, [ext, data])
    }

    eofCallback = (_: unknown, channel: number) => {
        this.eof$.next(channel)
    }

    closeCallback = (_: unknown, channel: number) => {
        this.close$.next(channel)
        // Data, extended data, EOF and close arrive through separate threadsafe functions, so a channel's last data
        // can be dispatched after its close. Keep its buffers for a while, so that late events still reach its
        // subscribers instead of a new buffer that nobody reads. (Channel IDs are not reused.)
        setTimeout(() => {
            this.data$.closeChannel(channel)
            this.extendedData$.closeChannel(channel)
            this.eof$.closeChannel(channel)
            this.close$.closeChannel(channel)
        }, LATE_EVENTS_GRACE_MS).unref?.()
    }

    disconnectCallback = () => {
        this.disconnect$.next()
    }

    x11ChannelOpenCallback = (_: unknown, channel: russh.NewSshChannel, address: string, port: number) => {
        this.x11ChannelOpen$.next([channel, address, port])
    }

    tcpChannelOpenCallback = (_: unknown, channel: russh.NewSshChannel, connectedAddress: string, connectedPort: number, originatorAddress: string, originatorPort: number) => {
        this.tcpChannelOpen$.next([channel, connectedAddress, connectedPort, originatorAddress, originatorPort])
    }

    agentChannelOpenCallback = (_: unknown, channel: russh.NewSshChannel) => {
        this.agentChannelOpen$.next([channel])
    }

    bannerCallback = (_: unknown, banner: string) => {
        this.banner$.next(banner)
        this.banner$.complete()
    }
}
