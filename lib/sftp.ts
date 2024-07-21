import { filter, map } from 'rxjs'
import * as russh from '../russh'
import { ClientEventInterface } from './events'
import { Destructible } from "./helpers"

export interface SFTPMetadata {
    size: number
    type: russh.SftpFileType
    uid?: number
    user?: string
    gid?: number
    group?: string
    permissions?: number
    atime?: number
    mtime?: number
}

export interface SFTPDirectoryEntry {
    name: string
    metadata: SFTPMetadata
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

    async readlink (path: string): Promise<string> {
        this.assertNotDestructed()
        return this.inner.readlink(path)
    }

    async rename (src: string, dst: string): Promise<void> {
        this.assertNotDestructed()
        await this.inner.rename(src, dst)
    }

    async stat (path: string): Promise<SFTPMetadata> {
        this.assertNotDestructed()
        const md = await this.inner.stat(path)
        return {
            ...md,
            type: md.type(),
            size: parseInt(md.size),
        }
    }

    async readDirectory (path: string): Promise<SFTPDirectoryEntry[]> {
        this.assertNotDestructed()
        let entries = await this.inner.readDir(path)
        return entries.map(e => {
            const md = e.metadata()
            return {
                name: e.name,
                metadata: {
                    // Can't just spread a napi object
                    type: e.type,
                    size: parseInt(md.size),
                    atime: md.atime,
                    mtime: md.mtime,
                    gid: md.gid,
                    group: md.group,
                    permissions: md.permissions,
                    uid: md.uid,
                    user: md.user,
                },
            }
        })
    }

    async chmod (path: string, mode: string|number): Promise<void> {
        this.assertNotDestructed()
        let parsed = typeof mode === 'string' ? parseInt(mode, 8) : mode
        await this.inner.chmod(path, parsed)
    }

    async close(): Promise<void> {
        await this.inner.close()
    }

    async open (path: string, mode: number): Promise<russh.SftpFile> {
        const f = await this.inner.open(path, mode)
        return f
    }
}
