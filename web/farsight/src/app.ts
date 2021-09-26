import * as fs from "fs";

import { ApolloServer, AuthenticationError } from "apollo-server-koa";
import * as argon2 from "argon2";
import { Request } from "koa";
import depthLimit from "graphql-depth-limit";
import * as jwt from "jsonwebtoken";
import Koa from "koa";
import KoaStatic from "koa-static";
import KoaMount from "koa-mount";
import { RateLimiterMemory } from "rate-limiter-flexible";

import {
    Database,
    getSiteById,
    getSiteOwner,
    getSitePages,
    getUserById,
    getUserPassword,
    getUserSites,
    importPage,
    makePage,
    makeSite,
    makeUser,
    pageSites,
    updateSiteConfig,
} from "./db";
import { LISTEN_PORT, SCHEMA_FILE, SECRET_KEY, FRONTEND_BASE, RATE_LIMIT_BYPASS } from "./config";
import { ApolloServerPluginLandingPageDisabled, ValidationError } from "apollo-server-core";

export type ResolverContext = {
    db: Database;
    user: number | undefined;
};

function getAuthedUser(req: Request): number | undefined {
    const bearer = req.headers.authorization?.split(" ", 2)[1];
    try {
        return bearer ? (<{ userId: number }>jwt.verify(bearer, SECRET_KEY)).userId : undefined;
    } catch {
        return undefined;
    }
}

async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
    try {
        return await argon2.verify(passwordHash, password);
    } catch {
        return false;
    }
}

export const server = new ApolloServer({
    typeDefs: fs.readFileSync(SCHEMA_FILE).toString(),
    resolvers: {
        Query: {
            async me(_, __, ctx: ResolverContext) {
                if (ctx.user === undefined) throw new AuthenticationError("No logged in user");

                return await getUserById(ctx.db, ctx.user);
            },
            async site(_, { id }, ctx: ResolverContext) {
                if (ctx.user === undefined) throw new AuthenticationError("Unauthorized");

                const site = await getSiteById(ctx.db, id);
                return site?.ownerId === ctx.user || site?.public ? site : null;
            },
        },
        Mutation: {
            async loginOrRegister(_, { username, password }, ctx: ResolverContext) {
                const hashedPassword = await argon2.hash(password);
                const createdUser = await makeUser(ctx.db, username, hashedPassword);
                if (createdUser !== undefined) {
                    await makeSite(ctx.db, createdUser, `${username}'s Site`);
                }

                const userInfo = await getUserPassword(ctx.db, username);
                if (!userInfo || !(await verifyPassword(userInfo.password, password))) {
                    throw new AuthenticationError("Incorrect credentials");
                }

                return jwt.sign({ userId: userInfo.id }, SECRET_KEY);
            },
            async newPage(_, { name, content, siteId }, ctx: ResolverContext) {
                if (ctx.user === undefined) throw new AuthenticationError("Unauthorized");

                const siteOwner = await getSiteOwner(ctx.db, siteId);
                if (siteOwner?.id !== ctx.user) throw new AuthenticationError("Forbidden");

                return await makePage(ctx.db, name, content, siteId);
            },
            async setSiteConfig(_, { config, siteId }, ctx: ResolverContext) {
                if (ctx.user === undefined) throw new AuthenticationError("Unauthorized");

                const siteOwner = await getSiteOwner(ctx.db, siteId);
                if (siteOwner?.id !== ctx.user) throw new AuthenticationError("Forbidden");

                return await updateSiteConfig(ctx.db, config, siteId);
            },
            async importPage(_, { pageId, siteId }, ctx: ResolverContext) {
                if (ctx.user === undefined) return null;

                const siteOwner = await getSiteOwner(ctx.db, siteId);
                if (siteOwner?.id !== ctx.user) throw new AuthenticationError("Forbidden");

                return await importPage(ctx.db, pageId, siteId);
            },
        },
        User: {
            async sites(parent, _, ctx: ResolverContext) {
                if (!parent) return [];
                return await getUserSites(ctx.db, parent.id);
            },
        },
        Site: {
            async owner(parent, _, ctx: ResolverContext) {
                if (!parent) return null;
                const site = await getSiteById(ctx.db, parent.id);
                return site && (await getUserById(ctx.db, site.ownerId));
            },
            async pages(parent, _, ctx: ResolverContext) {
                if (!parent) return [];
                return await getSitePages(ctx.db, parent.id);
            },
        },
        Page: {
            async ownerSite(parent, _, ctx: ResolverContext) {
                if (!parent) return null;
                return (await pageSites(ctx.db, parent.id)).owner;
            },
            async siteRefs(parent, _, ctx: ResolverContext) {
                if (!parent) return null;
                return (await pageSites(ctx.db, parent.id)).refs;
            },
        },
    },
    context: async ({ ctx: { request } }) => {
        return {
            db: await Database.getHandle(),
            user: getAuthedUser(request),
        };
    },
    validationRules: [depthLimit(8)],
    plugins: [
        ApolloServerPluginLandingPageDisabled(),
        {
            async requestDidStart() {
                return {
                    async willSendResponse({ context }) {
                        context.db && context.db.close();
                    },
                };
            },
        },
    ],
    formatError: (err) => {
        if (err.originalError instanceof AuthenticationError) {
            return Error("Unauthenticated");
        } else if (err instanceof ValidationError) {
            return Error("Invalid request. Make sure your request is not too deep (maxdepth=8).");
        } else {
            console.log(err);
            return Error("An error occurred");
        }
    },
});

(async function () {
    await server.start();

    const rateLimiters = {
        // 24 rps
        webapp: new RateLimiterMemory({
            points: 24,
            duration: 1,
        }),
        // 4 rps
        graphql: new RateLimiterMemory({
            points: 4,
            duration: 1,
        }),
    };

    const app = new Koa();
    app.use(async (ctx, next) => {
        // Bypass for token holders
        if (ctx.get("x-rate-limit-bypass") == RATE_LIMIT_BYPASS) {
            return await next();
        }

        const limiter = ctx.request.url === "/graphql" ? rateLimiters.graphql : rateLimiters.webapp;
        try {
            await limiter.consume(ctx.get('x-real-ip') || ctx.ip);
            return await next();
        } catch (_e) {
            ctx.status = 429;
            ctx.body = "Too many requests";
        }
    });
    server.applyMiddleware({ app, path: "/graphql" });
    app.use(KoaMount("/", KoaStatic(FRONTEND_BASE)));
    app.use(async (ctx, next) => {
        if (ctx.status === 404) {
            return ctx.redirect("/");
        }
        return await next();
    });
    app.use(async (ctx, next) => {
        ctx.set("X-Frame-Options", "deny");
        ctx.set("X-Content-Type-Option", "nosniff");
        ctx.set("Referrer-Policy", "no-referrer");
        // Omitting CSP since that might make people think its a XSS chal
        return await next();
    });

    app.listen(LISTEN_PORT);
})();
