export class Destructible {
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
