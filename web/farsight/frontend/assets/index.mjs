import { selectView, getCurrentUser } from "./util.mjs";
import { SiteBrowser } from "./browser.mjs";
import { graphql } from "./util.mjs";

(async function () {
    const router = new Navigo("/");
    const user = await getCurrentUser();

    const pageSel = document.querySelector("#page-list");
    const pageAdd = document.querySelector("#page-add");
    const heading = document.querySelector(".container > header > h1");
    const content = document.querySelector(".container > main");
    const pgModal = document.querySelector("#page-modal");
    const newPgFm = document.querySelector("#page-modal form");
    const cfModal = document.querySelector("#conf-modal");
    const confAdd = document.querySelector("#conf-add");

    pgModal.querySelector('[data-modal="close"]').addEventListener("click", () => (pgModal.style.display = "none"));
    cfModal.querySelector('[data-modal="close"]').addEventListener("click", () => (cfModal.style.display = "none"));

    router.on("/", () => router.navigate("/home"));
    router.on("/home", () => selectView("home"));
    router.on("/logout", () => {
        localStorage.removeItem("token");
        window.location.reload();
    });
    router.on("/browser", () => router.navigate(`/browser/${user.sites[0].id}`));
    router.on("/browser/:siteid", async (route) => {
        selectView("browser");

        const siteId = route.data.siteid;
        const browser = new SiteBrowser(siteId);
        await browser.loadSiteData();
        const pages = browser.listPages();

        if (pages.length > 0) {
            selectPage(pages[0].id);
        } else {
            heading.textContent = "No Pages Yet. Make one!";
        }

        pageSel.innerHTML = "";
        pages.forEach((page) => {
            const opt = document.createElement("option");
            opt.textContent = page.name;
            opt.value = page.id;
            pageSel.appendChild(opt);
        });

        content.removeAttribute("style");
        browser.getSite().config.map(({ key, value }) => content.style.setProperty(key, value));

        pageSel.onchange = () => selectPage(+pageSel.value);
        pageAdd.onclick = () => {
            pgModal.style.display = "block";
            pgModal.querySelector('[data-modal="submit"]').onclick = async () => {
                const data = Object.fromEntries(new FormData(newPgFm).entries());

                const res = await graphql(
                    `
                        mutation newPage($name: String, $content: String, $siteId: ID!) {
                            newPage(name: $name, content: $content, siteId: $siteId)
                        }
                    `,
                    { ...data, siteId }
                );

                newPgFm.reset();
                pgModal.style.display = "none";

                if (res.errors) {
                    console.error(res);
                    alert("An error occurred.");
                }

                router.navigate("/browser");
            };
        };

        confAdd.onclick = () => {
            cfModal.style.display = "block";
            const confArea = cfModal.querySelector("textarea");
            confArea.value = JSON.stringify(browser.getSite().config, null, 4);

            cfModal.querySelector('[data-modal="submit"]').onclick = async () => {
                try {
                    JSON.parse(confArea.value);
                } catch {
                    alert("Invalid JSON");
                    return;
                }

                const config = JSON.stringify(
                    Object.fromEntries(JSON.parse(confArea.value).map((conf) => [conf.key, conf.value]))
                );

                const res = await graphql(
                    `
                        mutation setSiteconfig($config: String!, $siteId: ID!) {
                            setSiteConfig(config: $config, siteId: $siteId)
                        }
                    `,
                    { config, siteId }
                );
                if (res.errors) {
                    console.error(res);
                    alert("An error occurred when updating config");
                }

                cfModal.style.display = "none";
            };
        };

        function selectPage(pageId) {
            const page = browser.getPage(pageId);
            heading.textContent = `${browser.getSite().name} / ${page.name}`;
            content.innerHTML = DOMPurify.sanitize(marked(page.content));
        }
    });

    router.resolve();
})();
