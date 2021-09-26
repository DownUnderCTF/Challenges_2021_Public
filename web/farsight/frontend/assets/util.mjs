export async function graphql(query, params = {}) {
    const res = await fetch("/graphql", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify({
            query,
            variables: params,
        }),
    });
    const jsonData = await res.json();
    return jsonData.data;
}

export async function getCurrentUser() {
    if (!localStorage.getItem("token")) {
        return null;
    }
    return (
        await graphql(
            `
                query me {
                    me {
                        username
                        sites {
                            id
                            name
                        }
                    }
                }
            `
        )
    ).me;
}

export function selectView(link) {
    const nav = document.querySelector("nav");
    Array.from(nav.querySelectorAll("a[href]")).forEach((e) => e.classList.remove("active"));
    Array.from(document.querySelectorAll("[data-view]")).forEach((e) => (e.style.display = "none"));

    nav.querySelector(`a[href="/${link}"]`).classList.add("active");
    document.querySelector(`[data-view="${link}"]`).style.display = "block";
}
