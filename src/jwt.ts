import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/**
 * Minimal HS256 JSON Web Tokens (RFC 7519) on node:crypto: no dependency. Used for access tokens.
 * Several secrets can be active: the first signs, every one verifies (rotate by prepending a new one,
 * then drop the old one after the access-token lifetime).
 */
export interface JwtOptions {
  /** One secret or a rotation list (first signs). Each at least 32 characters. */
  secret: string | string[];
  issuer?: string;
  audience?: string;
}

export interface AccessClaims {
  /** user id */
  sub: string;
  /** organisation id */
  org: string;
  /** session id (revocable server-side) */
  sid: string;
  iat: number;
  exp: number;
  iss?: string;
  aud?: string;
}

const b64 = (v: string | Buffer) => Buffer.from(v).toString("base64url");
const kidOf = (secret: string) => createHash("sha256").update(secret).digest("base64url").slice(0, 8);

export function jwtSigner(o: JwtOptions) {
  const secrets = (Array.isArray(o.secret) ? o.secret : [o.secret]).filter(Boolean);
  if (!secrets.length) throw new Error("jwt: give at least one secret");
  for (const s of secrets) if (s.length < 32) throw new Error("jwt: every secret needs at least 32 characters");
  const keys = new Map(secrets.map((s) => [kidOf(s), s]));
  const signer = secrets[0]!;
  const mac = (secret: string, data: string) => createHmac("sha256", secret).update(data).digest();

  return {
    sign(claims: Omit<AccessClaims, "iss" | "aud">): string {
      const header = b64(JSON.stringify({ alg: "HS256", typ: "JWT", kid: kidOf(signer) }));
      const body = b64(JSON.stringify({ ...claims, ...(o.issuer ? { iss: o.issuer } : {}), ...(o.audience ? { aud: o.audience } : {}) }));
      return `${header}.${body}.${b64(mac(signer, `${header}.${body}`))}`;
    },

    /** Claims when the signature, issuer and audience hold; null otherwise. `ignoreExpiry` is for logout. */
    verify(token: string, opts: { now?: number; ignoreExpiry?: boolean } = {}): AccessClaims | null {
      if (token.length > 2048) return null;
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      const [h, p, s] = parts as [string, string, string];
      let header: { alg?: string; kid?: string };
      let claims: AccessClaims;
      try {
        header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
        claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
      } catch {
        return null;
      }
      if (header.alg !== "HS256") return null; // never "none", never an algorithm chosen by the token
      const candidates = header.kid && keys.has(header.kid) ? [keys.get(header.kid)!] : secrets;
      const sig = Buffer.from(s, "base64url");
      const ok = candidates.some((secret) => {
        const expected = mac(secret, `${h}.${p}`);
        return expected.length === sig.length && timingSafeEqual(expected, sig);
      });
      if (!ok) return null;
      if (typeof claims.sub !== "string" || typeof claims.org !== "string" || typeof claims.sid !== "string" || typeof claims.exp !== "number") return null;
      if (o.issuer && claims.iss !== o.issuer) return null;
      if (o.audience && claims.aud !== o.audience) return null;
      const now = Math.floor((opts.now ?? Date.now()) / 1000);
      if (!opts.ignoreExpiry && claims.exp <= now) return null;
      return claims;
    },
  };
}

/** A JWT has three dot-separated parts; opaque tokens (base64url) have none. */
export const looksLikeJwt = (token: string) => token.split(".").length === 3;
