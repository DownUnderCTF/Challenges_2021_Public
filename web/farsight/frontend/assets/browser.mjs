import { graphql } from "./util.mjs";

export class SiteBrowser {
    constructor(siteId) {
        this.token = localStorage.getItem("token");
        this.siteId = siteId;
        this.siteInfo = undefined;
    }

    async loadSiteData() {
        this.siteInfo = (
            await graphql(
                `
                    query site($site: ID!) {
                        site(id: $site) {
                            id
                            name
                            public
                            owner {
                                id
                            }
                            config {
                                key
                                value
                            }
                            pages {
                                id
                                name
                                content
                            }
                        }
                    }
                `,
                { site: this.siteId }
            )
        ).site;
    }

    listPages() {
        return this.siteInfo.pages;
    }

    getPage(pageId) {
        return this.siteInfo.pages.find((p) => +p.id === +pageId);
    }

    getSite() {
        return this.siteInfo;
    }
}
