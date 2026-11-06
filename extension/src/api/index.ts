import type { ApiClient } from "./types";
import { HttpApiClient } from "./httpClient";

export { HttpApiClient };
export const api: ApiClient = new HttpApiClient();
