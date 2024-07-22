import type * as Russh from '../russh'
import { Observable, mergeMap, from } from 'rxjs'
import { Destructible } from './helpers'
import { SFTP } from './sftp'
import { Channel } from './channel'
import { ClientEventInterface } from './events'

let russh: Russh

let triple = process.env.RUST_TARGET_TRIPLE || {
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

try {
    russh = require(`../target/russh-${triple}.node`)
} catch {
    russh = require('../target/russh.node')
}


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

    async openSFTPChannel(): Promise<SFTP> {
        return new SFTP(await this.client.channelOpenSftp(), this.events)
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
    SftpFileType as SFTPFileType,
    supportedCiphers as getSupportedCiphers,
    supportedKexAlgorithms as getSupportedKexAlgorithms,
    supportedMacs as getSupportedMACs,
    supportedCompressionAlgorithms as getSupportedCompressionAlgorithms,
    supportedKeyTypes as getSupportedKeyTypes,
    OPEN_APPEND, OPEN_CREATE, OPEN_READ, OPEN_TRUNCATE, OPEN_WRITE,
    SftpFile as SFTPFile,
} from '../russh'
export {
    SFTP, SFTPDirectoryEntry, SFTPMetadata,
} from './sftp'
export { Channel }
