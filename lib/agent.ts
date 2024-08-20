import { filter, Subject } from 'rxjs'
import { Destructible } from './helpers'
import * as russh from './native'

export type AgentConnectionSpec = {
    kind: 'pageant',
} | {
    kind: 'named-pipe',
    path: string,
} | {
    kind: 'unix-socket',
    path: string
}

export function makeRusshAgentConnection (spec: AgentConnectionSpec): russh.AgentConnection {
    return russh.AgentConnection.new(
        {
            pageant: russh.AgentConnectionKind.Pageant,
            'named-pipe': russh.AgentConnectionKind.Pipe,
            'unix-socket': russh.AgentConnectionKind.Unix,
        }[spec.kind],
        spec.kind === 'pageant' ? undefined : spec.path,
    )
}

export class SSHAgentStream extends Destructible {
    data$ = this.data.asObservable().pipe(filter(data => data.length > 0))

    private constructor (
        private inner: russh.SshAgentStream,
        private data: Subject<Uint8Array>,
    ) {
        super()
        this.data.subscribe(data => {
            if (data.length === 0) {
                this.destruct()
            }
        })
    }

    protected override destruct() {
        super.destruct()
        this.data.complete()
    }

    async write (data: Uint8Array): Promise<void> {
        this.assertNotDestructed()
        await this.inner.write(data)
    }

    async close (): Promise<void> {
        this.assertNotDestructed()
        await this.inner.close()
        this.destruct()
    }

    static async connect(spec: AgentConnectionSpec): Promise<SSHAgentStream> {
        let dataSubject = new Subject<Uint8Array>()
        return new SSHAgentStream(await russh.connectAgent(
            makeRusshAgentConnection(spec),
            (_, data) => {
                dataSubject.next(data)
            }
        ), dataSubject)
    }
}
