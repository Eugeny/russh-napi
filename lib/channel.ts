import * as russh from './native'
import { Observable, filter, map } from 'rxjs'
import { Destructible } from './helpers'
import { ClientEventInterface } from './events'

export interface PTYSize {
    columns: number,
    rows: number,
    pixWidth: number,
    pixHeight: number,
}

export interface X11Options {
    singleConnection: boolean,
    authProtocol: string,
    authCookie: string,
    screenNumber: number,
}

export class Channel extends Destructible {
    readonly data$: Observable<Uint8Array>
    readonly extendedData$: Observable<[number, Uint8Array]>
    readonly eof$: Observable<void>
    readonly closed$: Observable<void>

    constructor(
        public readonly id: number,
        private inner: russh.SshChannel,
        events: ClientEventInterface,
    ) {
        super()
        this.data$ = events.data$.pipe(filter(([channel]) => channel === id), map(([_, data]) => data))
        this.extendedData$ = events.extendedData$.pipe(filter(([channel]) => channel === id), map(([_, ext, data]) => [ext, data]))
        this.eof$ = events.eof$.pipe(filter(channel => channel === id), map(() => { }))
        this.closed$ = events.close$.pipe(filter(channel => channel === id), map(() => { }))
    }

    async requestShell(): Promise<void> {
        this.assertNotDestructed()
        await this.inner.requestShell()
    }

    async requestExec(command: string): Promise<void> {
        this.assertNotDestructed()
        await this.inner.requestExec(command)
    }

    async requestPTY(
        terminal: string,
        opts: PTYSize,
    ): Promise<void> {
        this.assertNotDestructed()
        await this.inner.requestPty(
            terminal,
            opts.columns,
            opts.rows,
            opts.pixWidth,
            opts.pixHeight
        )
    }

    async requestX11Forwarding(options: X11Options): Promise<void> {
        this.assertNotDestructed()
        await this.inner.requestX11Forwarding(
            options.singleConnection,
            options.authProtocol,
            options.authCookie,
            options.screenNumber
        )
    }

    async resizePTY(size: PTYSize): Promise<void> {
        this.assertNotDestructed()
        await this.inner.windowChange(
            size.columns,
            size.rows,
            size.pixWidth,
            size.pixHeight
        )
    }

    async write(data: Uint8Array): Promise<void> {
        this.assertNotDestructed()
        await this.inner.data(data)
    }

    async eof(): Promise<void> {
        await this.inner.eof()
    }

    async close(): Promise<void> {
        await this.inner.close()
    }
}
