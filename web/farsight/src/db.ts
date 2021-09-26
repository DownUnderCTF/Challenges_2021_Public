import { Pool, PoolClient } from "pg";

export type User = {
    id: number;
    username: string;
};

export type Site = {
    id: number;
    name: string;
    public: boolean;
    config: { key: string; value: string }[];
    ownerId: number;
};

export type Page = {
    id: number;
    name: string;
    content: string;
};

const dbPool = new Pool();

export class Database {
    #client: PoolClient;
    constructor(client: PoolClient) {
        this.#client = client;
    }

    async get(query: string, args: any[]) {
        const rows = await this.all(query, args);
        return rows.length > 0 ? rows[0] : undefined;
    }

    async all(query: string, args: any[]) {
        return (await this.run(query, args)).rows;
    }

    async run(query: string, args: any[]) {
        return await this.#client.query(query, args);
    }

    close() {
        this.#client.release();
    }

    static async getHandle() {
        return new Database(await dbPool.connect());
    }
}

function configFromString(configStr: string) {
    return Object.entries(<{ [k: string]: string }>JSON.parse(configStr)).map(([k, v]) => ({ key: k, value: v }));
}

export async function getUserById(db: Database, userId: number): Promise<User | undefined> {
    return await db.get(`SELECT id, username FROM "user" WHERE id=$1`, [userId]);
}

export async function getSiteById(db: Database, siteId: number): Promise<Site | undefined> {
    const site = await db.get("SELECT id, * FROM site WHERE id=$1", [siteId]);
    return {
        id: site.id,
        name: site.name,
        public: site.public,
        config: configFromString(site.config),
        ownerId: site.owner,
    };
}

export async function getUserSites(db: Database, ownerId: number): Promise<Site[]> {
    return (await db.all("SELECT id, * FROM site WHERE owner=$1", [ownerId])).map((site) => ({
        id: site.id,
        name: site.name,
        public: site.public,
        config: configFromString(site.config),
        ownerId,
    }));
}

export async function getSitePages(db: Database, siteId: number): Promise<Page[]> {
    return (
        await db.all("SELECT id, * FROM page WHERE site=$1 OR id IN (SELECT page FROM page_ref WHERE site=$1)", [
            siteId,
        ])
    ).map((page) => ({
        id: page.id,
        name: page.name,
        content: page.content,
    }));
}

export async function pageSites(db: Database, pageId: number): Promise<{ owner: Site; refs: Site[] }> {
    const owningSite = await db.get("SELECT id, * FROM site WHERE id=(SELECT site FROM page WHERE id=$1)", [pageId]);
    const refedSites = await db.all("SELECT id, * FROM site WHERE id IN (SELECT site FROM page_ref WHERE page=$1)", [
        pageId,
    ]);

    return {
        owner: {
            id: owningSite.id,
            name: owningSite.name,
            public: owningSite.public,
            config: configFromString(owningSite.config),
            ownerId: owningSite.owner,
        },
        refs: refedSites.map((site) => ({
            id: site.id,
            name: site.name,
            public: site.public,
            config: configFromString(site.config),
            ownerId: site.owner,
        })),
    };
}

export async function getUserPassword(
    db: Database,
    username: string
): Promise<{ id: number; password: string } | undefined> {
    const userInfo = await db.get(`SELECT id, password FROM "user" WHERE username=$1`, [username]);
    return (
        userInfo && {
            id: userInfo.id,
            password: userInfo.password,
        }
    );
}

export async function getSiteOwner(db: Database, siteId: number): Promise<User | undefined> {
    const ownerId = await db.get("SELECT owner FROM site WHERE id=$1", [siteId]);
    return await getUserById(db, ownerId.owner);
}

export async function makeUser(db: Database, username: string, password: string): Promise<number | undefined> {
    try {
        const res = await db.get(`INSERT INTO "user" (username, password) VALUES ($1, $2) RETURNING id`, [
            username,
            password,
        ]);
        return res.id;
    } catch (e: any) {
        // unique contraint
        if (e.code !== "23505") {
            throw e;
        }
    }
}

export async function makeSite(db: Database, userId: number, name: string): Promise<number | undefined> {
    const res = await db.get("INSERT INTO site (name, public, config, owner) VALUES ($1, $2, $3, $4) RETURNING id", [
        name,
        false,
        JSON.stringify({ background: "white", color: "black" }),
        userId,
    ]);
    return res.id;
}

export async function updateSiteConfig(db: Database, config: String, siteId: number): Promise<number | undefined> {
    await db.run("UPDATE site SET config=$1 WHERE id=$2", [config, siteId]);
    return 1;
}

export async function makePage(db: Database, name: string, ctnt: string, siteId: number): Promise<number | undefined> {
    const res = await db.get("INSERT INTO page(name, content, site) VALUES ($1, $2, $3) RETURNING id", [
        name,
        ctnt,
        siteId,
    ]);

    return res.id;
}

export async function importPage(db: Database, pageId: number, siteId: number): Promise<number | undefined> {
    await db.run("INSERT INTO page_ref (site, page) VALUES ($1, $2)", [siteId, pageId]);
    return 1;
}
