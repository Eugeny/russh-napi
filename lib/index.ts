import * as russh from '../russh'
import { Subject, Observable, filter, map, mergeMap, from, AsyncSubject } from 'rxjs'

export class KeyPair {
    private constructor(protected inner: russh.SshKeyPair) { }

    static async parse(data: string, passphrase?: string): Promise<KeyPair> {
        return new KeyPair(await russh.parseKey(data, passphrase))
    }
}

export interface X11ChannelOpenEvent {
    readonly channel: Channel
    readonly clientAddress: string
    readonly clientPort: number
}

export interface TCPChannelOpenEvent {
    readonly channel: Channel
    readonly targetAddress: string
    readonly targetPort: number
    readonly clientAddress: string
    readonly clientPort: number
}

class ClientEventInterface {
    data$ = new Subject<[number, Uint8Array]>()
    eof$ = new Subject<number>()
    close$ = new Subject<number>()
    disconnect$ = new Subject<void>()
    x11ChannelOpen$ = new Subject<[russh.SshChannel, string, number]>()
    tcpChannelOpen$ = new Subject<[russh.SshChannel, string, number, string, number]>()
    banner$ = new AsyncSubject<string>()

    complete() {
        this.data$.complete()
        this.eof$.complete()
        this.close$.complete()
        this.disconnect$.complete()
        this.x11ChannelOpen$.complete()
        this.tcpChannelOpen$.complete()
        this.banner$.complete()
    }

    dataCallback = (_: unknown, channel: number, data: Uint8Array) => {
        this.data$.next([channel, data])
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

    bannerCallback = (_: unknown, banner: string) => {
        this.banner$.next(banner)
        this.banner$.complete()
    }
}

class Destructible {
    private destructed = false

    protected destruct() {
        if (this.destructed) {
            return
        }
        this.destructed = true
    }

    protected assertNotDestructed() {
        if (this.destructed) {
            throw new Error('Object has been destructed')
        }
    }
}

export type KeyboardInteractiveAuthenticationState = {
    state: 'failure',
} | {
    state: 'infoRequest'
    name: string
    instructions: string
    prompts: () => russh.KeyboardInteractiveAuthenticationPrompt[]
}

export interface Config {
    preferred?: {
        ciphers?: string[]
        kex?: string[],
        key?: string[],
        mac?: string[],
        compression?: string[],
    },
}

export class SSHClient extends Destructible {
    readonly disconnect$ = this.events.disconnect$.asObservable()
    readonly banner$ = this.events.banner$.asObservable()

    private constructor(
        private client: russh.SshClient,
        private events: ClientEventInterface,
    ) { super() }

    static async connect(
        transport: russh.SshTransport,
        serverKeyCallback: (key: russh.SshPublicKey) => Promise<boolean>,
        config?: Config,
    ): Promise<SSHClient> {
        const eventInterface = new ClientEventInterface()

        const russhClient = await russh.connect(
            transport,
            config?.preferred?.ciphers,
            config?.preferred?.kex,
            config?.preferred?.key,
            config?.preferred?.mac,
            config?.preferred?.compression,
            (_, k) => serverKeyCallback(k),
            eventInterface.dataCallback,
            eventInterface.eofCallback,
            eventInterface.closeCallback,
            eventInterface.disconnectCallback,
            eventInterface.x11ChannelOpenCallback,
            eventInterface.tcpChannelOpenCallback,
            eventInterface.bannerCallback,
        )

        eventInterface.disconnect$.subscribe(() => {
            eventInterface.complete()
        })

        return new SSHClient(russhClient, eventInterface)
    }

    protected override destruct(): void {
        super.destruct()
    }

    async authenticateWithPassword(username: string, password: string): Promise<AuthenticatedSSHClient | null> {
        this.assertNotDestructed()
        const result = await this.client.authenticatePassword(username, password)
        if (result) {
            return this.intoAuthenticated()
        }
        return null
    }

    async authenticateWithKeyPair(username: string, keyPair: KeyPair): Promise<AuthenticatedSSHClient | null> {
        this.assertNotDestructed()
        const result = await this.client.authenticatePublickey(username, keyPair['inner'])
        if (result) {
            return this.intoAuthenticated()
        }
        return null
    }

    async startKeyboardInteractiveAuthentication(username: string): Promise<KeyboardInteractiveAuthenticationState> {
        this.assertNotDestructed()
        return await this.client.startKeyboardInteractiveAuthentication(username) as unknown as KeyboardInteractiveAuthenticationState
    }

    async continueKeyboardInteractiveAuthentication(responses: string[]): Promise<AuthenticatedSSHClient | KeyboardInteractiveAuthenticationState> {
        this.assertNotDestructed()
        const result = await this.client.respondToKeyboardInteractiveAuthentication(responses)
        if (result.state === 'success') {
            return this.intoAuthenticated()
        }
        return result as unknown as KeyboardInteractiveAuthenticationState
    }

    async disconnect(): Promise<void> {
        this.destruct()
        await this.client.disconnect()
    }

    private intoAuthenticated(): AuthenticatedSSHClient {
        this.destruct()
        return new AuthenticatedSSHClient(this.client, this.events)
    }
}

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
    readonly eof$: Observable<void>
    readonly closed$: Observable<void>

    constructor(
        public readonly id: number,
        private inner: russh.SshChannel,
        events: ClientEventInterface,
    ) {
        super()
        this.data$ = events.data$.pipe(filter(([channel]) => channel === id), map(([_, data]) => data))
        this.eof$ = events.eof$.pipe(filter(channel => channel === id), map(() => { }))
        this.closed$ = events.close$.pipe(filter(channel => channel === id), map(() => { }))
    }

    async requestShell(): Promise<void> {
        await this.inner.requestShell()
    }

    async requestPTY(
        terminal: string,
        opts: PTYSize,
    ): Promise<void> {
        await this.inner.requestPty(
            terminal,
            opts.columns,
            opts.rows,
            opts.pixWidth,
            opts.pixHeight
        )
    }

    async requestX11Forwarding(options: X11Options): Promise<void> {
        await this.inner.requestX11Forwarding(
            options.singleConnection,
            options.authProtocol,
            options.authCookie,
            options.screenNumber
        )
    }

    async resizePTY(size: PTYSize): Promise<void> {
        await this.inner.windowChange(
            size.columns,
            size.rows,
            size.pixWidth,
            size.pixHeight
        )
    }

    async write(data: Uint8Array): Promise<void> {
        await this.inner.data(data)
    }

    async eof(): Promise<void> {
        await this.inner.eof()
    }

    async close(): Promise<void> {
        await this.inner.close()
    }
}

export class AuthenticatedSSHClient extends Destructible {
    readonly disconnect$: Observable<void> = this.events.disconnect$
    readonly x11ChannelOpen$: Observable<X11ChannelOpenEvent> =
        this.events.x11ChannelOpen$.pipe(mergeMap(([ch, address, port]) =>
            from(this.wrapChannel(ch).then(channel => ({
                channel,
                clientAddress: address,
                clientPort: port,
            })))))

    readonly tcpChannelOpen$: Observable<TCPChannelOpenEvent> = this.events.tcpChannelOpen$.pipe(mergeMap(([
        ch,
        targetAddress,
        targetPort,
        clientAddress,
        clientPort,
    ]) =>
        from(this.wrapChannel(ch).then(channel => ({
            channel,
            targetAddress,
            targetPort,
            clientAddress,
            clientPort,
        })))))

    constructor(
        private client: russh.SshClient,
        private events: ClientEventInterface,
    ) { super() }

    async openSessionChannel(): Promise<Channel> {
        return await this.wrapChannel(await this.client.channelOpenSession())
    }

    async openTCPForwardChannel(options: {
        addressToConnectTo: string,
        portToConnectTo: number,
        originatorAddress: string,
        originatorPort: number,
    }): Promise<Channel> {
        return await this.wrapChannel(await this.client.channelOpenDirectTcpip(
            options.addressToConnectTo,
            options.portToConnectTo,
            options.originatorAddress,
            options.originatorPort,
        ))
    }

    async forwardTCPPort(
        addressToBind: string,
        portToBind: number,
    ): Promise<number> {
        return await this.client.tcpipForward(
            addressToBind,
            portToBind,
        )
    }

    async stopForwardingTCPPort(
        addressToBind: string,
        portToBind: number,
    ): Promise<void> {
        await this.client.cancelTcpipForward(
            addressToBind,
            portToBind,
        )
    }

    async disconnect(): Promise<void> {
        this.destruct()
        await this.client.disconnect()
    }

    private async wrapChannel(channel: russh.SshChannel): Promise<Channel> {
        let id = await channel.id()
        return new Channel(id, channel, this.events)
    }
}

export {
    KeyboardInteractiveAuthenticationPrompt,
    SshPublicKey,
    SshTransport,
    supportedCiphers as getSupportedCiphers,
    supportedKexAlgorithms as getSupportedKexAlgorithms,
    supportedMacs as getSupportedMACs,
    supportedCompressionAlgorithms as getSupportedCompressionAlgorithms,
    supportedKeyTypes as getSupportedKeyTypes,
} from '../russh'
