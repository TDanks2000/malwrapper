import * as crypto from "node:crypto";
import { BASE_URL } from "./utils";

class Auth {
  client_id: string;
  state: string;
  redirect_uri: string;
  code_challenge_method?: string;
  response_type: string = "code";

  constructor(
    client_id: string,
    state: string,
    redirect_uri: string,
    code_challenge_method?: string,
    response_type?: string
  ) {
    this.client_id = client_id;
    this.state = state;
    this.redirect_uri = redirect_uri;
    if (code_challenge_method) this.code_challenge_method = code_challenge_method;
    if (response_type) this.response_type = response_type;
  }

  private generate_code_verifier() {
    return this.base64URLEncode(crypto.randomBytes(32));
  }

  private base64URLEncode(buffer: Buffer): string {
    return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  private sha256(buffer: Buffer): Buffer {
    return crypto.createHash("sha256").update(buffer).digest();
  }

  public generate_code_challenge() {
    return this.base64URLEncode(this.sha256(Buffer.from(this.generate_code_verifier())));
  }

  public generate_auth_url() {
    return `${BASE_URL}/v1/oauth2/authorize?response_type=${this.response_type}&client_id=${
      this.client_id
    }&code_challenge=${this.generate_code_challenge()}&code_challenge_method=${
      this.code_challenge_method ?? "plain"
    }`;
  }
}

export { Auth };
