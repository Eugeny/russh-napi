import { filter, map } from 'rxjs'
import * as russh from '../russh'
import { ClientEventInterface } from './events'
import { Destructible } from "./helpers"

export type SFTPDirectoryEntry = Omit<russh.SftpDirEntry, 'size'> & {
    objectSize: number
}

export class SFTP extends Destructible {
    readonly closed$ = this.events.close$.pipe(filter(channel => channel === this.inner.channelId), map(() => { }))

    constructor (
        private inner: russh.SftpChannel,
        private events: ClientEventInterface,
    ) { super() }

    async createDirectory (path: string): Promise<void> {
        this.assertNotDestructed()
        await this.inner.createDir(path)
    }

    async removeDirectory (path: string): Promise<void> {
        this.assertNotDestructed()
        await this.inner.removeDir(path)
    }

    async removeFile (path: string): Promise<void> {
        this.assertNotDestructed()
        await this.inner.removeFile(path)
    }

    async readDirectory (path: string): Promise<SFTPDirectoryEntry[]> {
        this.assertNotDestructed()
        let entries = await this.inner.readDir(path)
        for (const e of entries) {
            (e as any).objectSize = parseInt(e.size)
        }
        return entries as any
    }

    async close(): Promise<void> {
        await this.inner.close()
    }
}
