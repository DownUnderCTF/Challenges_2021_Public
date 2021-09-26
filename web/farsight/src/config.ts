import path from "path";

export const SECRET_KEY = process.env["SECRET_KEY"] || "pqFCx8hMn7t2haovHW38tj-gRVbPCIv0vHHP3luRvUA";
export const RATE_LIMIT_BYPASS = process.env["RATE_LIMIT_BYPASS"] || "x0vpwHou6Z8c7dMDWT5FygR4H1A_YyrrgC7SxzfNCdk";
export const LISTEN_PORT = 8000;

export const SCHEMA_FILE = getRelPath("./assets/schema.gql");
export const FRONTEND_BASE = getRelPath("../frontend");

function getRelPath(asset: string) {
    return path.resolve(__dirname, asset);
}
