import { describe, it, expect, beforeAll } from "bun:test";

const BASE_URL = "http://localhost:3000";

const uniqueSuffix = Date.now();
const TEST_USER = {
  username: `testuser_${uniqueSuffix}`,
  password: "testPassword123!",
  email: `testuser_${uniqueSuffix}@test.com`,
};

function extractCookie(res: Response, name: string): string | null {
  const setCookies = res.headers.getAll("set-cookie");
  for (const header of setCookies) {
    if (header.startsWith(`${name}=`)) {
      return header.split(";")[0];
    }
  }
  return null;
}

function extractCookieValue(res: Response, name: string): string | null {
  const cookie = extractCookie(res, name);
  if (!cookie) return null;
  return cookie.split("=").slice(1).join("=");
}

async function registerTestUser(user = TEST_USER) {
  await fetch(`${BASE_URL}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(user),
  });
}

async function loginTestUser(user = TEST_USER) {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: user.username,
      password: user.password,
    }),
  });
  if (!res.ok) throw new Error(`Login failed: ${res.status} ${await res.text()}`);
  const data = await res.json() as {
    message: string;
    accessToken: string;
    user: { id: number; username: string; email: string };
  };
  const refreshCookie = extractCookie(res, "refreshToken");
  if (!refreshCookie) throw new Error("No refreshToken cookie in login response");
  return { ...data, refreshCookie };
}

// ─── Health ──────────────────────────────────────────────

describe("Health Check", () => {
  it("GET /health — returns status ok", async () => {
    const res = await fetch(`${BASE_URL}/health`);
    expect(res.status).toBe(200);

    const data = await res.json();
    expect(data.status).toBe("ok");
    expect(data.timestamp).toBeDefined();
  });
});

// ─── Register ────────────────────────────────────────────

describe("Auth - Register", () => {
  it("POST /auth/register — registers a new user", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(TEST_USER),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe("User registered successfully");
    expect(data.user).toBeDefined();
    expect(data.user.username).toBe(TEST_USER.username);
    expect(data.user.email).toBe(TEST_USER.email);
    expect(data.user.password).toBeUndefined();
  });

  it("POST /auth/register — rejects duplicate username", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(TEST_USER),
    });

    expect(res.status).not.toBe(200);
  });

  it("POST /auth/register — rejects duplicate email", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: `different_${uniqueSuffix}`,
        password: "password12345",
        email: TEST_USER.email,
      }),
    });

    expect(res.status).not.toBe(200);
  });

  it("POST /auth/register — rejects missing fields", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "incomplete" }),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/register — rejects invalid email format", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: `invalidemail_${uniqueSuffix}`,
        password: "password12345",
        email: "not-an-email",
      }),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/register — rejects short username (< 3 chars)", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "ab",
        password: "password12345",
        email: `short_${uniqueSuffix}@test.com`,
      }),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/register — rejects short password (< 8 chars)", async () => {
    const res = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: `shortpw_${uniqueSuffix}`,
        password: "1234567",
        email: `shortpw_${uniqueSuffix}@test.com`,
      }),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ─── Login ───────────────────────────────────────────────

describe("Auth - Login", () => {
  const loginUser = {
    username: `loginuser_${uniqueSuffix}`,
    password: "loginPass123!",
    email: `loginuser_${uniqueSuffix}@test.com`,
  };

  beforeAll(async () => {
    await registerTestUser(loginUser);
  });

  it("POST /auth/login — returns accessToken in body and refreshToken as httpOnly cookie", async () => {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: loginUser.username,
        password: loginUser.password,
      }),
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe("Login successful");
    expect(data.accessToken).toBeDefined();
    expect(data.accessToken).toBeString();
    expect(data.user).toBeDefined();
    expect(data.user.username).toBe(loginUser.username);
    expect(data.user.email).toBe(loginUser.email);
    expect(data.user.password).toBeUndefined();

    expect(data.refreshToken).toBeUndefined();

    const cookie = extractCookie(res, "refreshToken");
    expect(cookie).not.toBeNull();

    const setCookies = res.headers.getAll("set-cookie");
    const rtHeader = setCookies.find((h) => h.startsWith("refreshToken="));
    expect(rtHeader).toBeDefined();
    expect(rtHeader).toContain("HttpOnly");
    expect(rtHeader).toContain("Path=/auth");
  });

  it("POST /auth/login — rejects wrong password with 401", async () => {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: loginUser.username,
        password: "wrongPassword!",
      }),
    });

    expect(res.status).toBe(401);
  });

  it("POST /auth/login — rejects non-existent user with same 401 (no user enumeration)", async () => {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "nonexistent_user_xyz",
        password: "anyPassword!",
      }),
    });

    expect(res.status).toBe(401);
  });

  it("POST /auth/login — wrong password and non-existent user return the same error", async () => {
    const [wrongPwRes, noUserRes] = await Promise.all([
      fetch(`${BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginUser.username,
          password: "wrongPassword!",
        }),
      }),
      fetch(`${BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: "nonexistent_user_xyz",
          password: "anyPassword!",
        }),
      }),
    ]);

    expect(wrongPwRes.status).toBe(noUserRes.status);
  });

  it("POST /auth/login — rejects missing fields", async () => {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: loginUser.username }),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/login — rejects empty body", async () => {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/login — rejects short password (< 8 chars, validation)", async () => {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: loginUser.username,
        password: "short",
      }),
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ─── Me (Protected Route) ───────────────────────────────

describe("Auth - Me (Protected Route)", () => {
  const meUser = {
    username: `meuser_${uniqueSuffix}`,
    password: "mePass12345!",
    email: `meuser_${uniqueSuffix}@test.com`,
  };
  let validAccessToken: string;

  beforeAll(async () => {
    await registerTestUser(meUser);
    const data = await loginTestUser(meUser);
    validAccessToken = data.accessToken;
  });

  it("GET /auth/me — returns user with valid token", async () => {
    const res = await fetch(`${BASE_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${validAccessToken}` },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.id).toBeDefined();
    expect(data.username).toBe(meUser.username);
    expect(data.email).toBe(meUser.email);
    expect(data.password).toBeUndefined();
  });

  it("GET /auth/me — rejects request without token (401)", async () => {
    const res = await fetch(`${BASE_URL}/auth/me`);

    expect(res.status).toBe(401);
  });

  it("GET /auth/me — rejects request with invalid token (401)", async () => {
    const res = await fetch(`${BASE_URL}/auth/me`, {
      headers: { Authorization: "Bearer invalid.jwt.token" },
    });

    expect(res.status).toBe(401);
  });

  it("GET /auth/me — rejects request with malformed Authorization header", async () => {
    const res = await fetch(`${BASE_URL}/auth/me`, {
      headers: { Authorization: "NotBearer sometoken" },
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ─── Refresh Token (via cookie) ─────────────────────────

describe("Auth - Refresh Token", () => {
  const refreshUser = {
    username: `refreshuser_${uniqueSuffix}`,
    password: "refreshPass123!",
    email: `refreshuser_${uniqueSuffix}@test.com`,
  };

  beforeAll(async () => {
    await registerTestUser(refreshUser);
  });

  it("POST /auth/refresh — issues new tokens with valid cookie", async () => {
    const { accessToken: oldAccessToken, refreshCookie } = await loginTestUser(refreshUser);

    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.accessToken).toBeDefined();
    expect(data.accessToken).toBeString();
    expect(data.accessToken).not.toBe(oldAccessToken);

    expect(data.refreshToken).toBeUndefined();

    const newCookie = extractCookie(res, "refreshToken");
    expect(newCookie).not.toBeNull();
    expect(newCookie).not.toBe(refreshCookie);
  });

  it("POST /auth/refresh — new access token works on protected route", async () => {
    const { refreshCookie } = await loginTestUser(refreshUser);

    const refreshRes = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });
    expect(refreshRes.status).toBe(200);
    const refreshData = await refreshRes.json();

    const meRes = await fetch(`${BASE_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${refreshData.accessToken}` },
    });

    expect(meRes.status).toBe(200);
    const meData = await meRes.json();
    expect(meData.username).toBe(refreshUser.username);
  });

  it("POST /auth/refresh — rejects already-used (revoked) refresh token", async () => {
    const { refreshCookie } = await loginTestUser(refreshUser);

    await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });

    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/refresh — rejects request without cookie", async () => {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/refresh — rejects invalid cookie value", async () => {
    const res = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: "refreshToken=completely.invalid.token" },
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

// ─── Logout (via cookie) ────────────────────────────────

describe("Auth - Logout", () => {
  const logoutUser = {
    username: `logoutuser_${uniqueSuffix}`,
    password: "logoutPass123!",
    email: `logoutuser_${uniqueSuffix}@test.com`,
  };

  beforeAll(async () => {
    await registerTestUser(logoutUser);
  });

  it("POST /auth/logout — logs out and clears cookie", async () => {
    const { refreshCookie } = await loginTestUser(logoutUser);

    const res = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe("Logged out successfully");

    const setCookies = res.headers.getAll("set-cookie");
    const rtHeader = setCookies.find((h) => h.startsWith("refreshToken="));
    if (rtHeader) {
      const cleared =
        rtHeader.includes("Max-Age=0") ||
        rtHeader.includes("Expires=Thu, 01 Jan 1970") ||
        rtHeader.includes("refreshToken=;") ||
        rtHeader.includes("refreshToken=deleted");
      expect(cleared).toBe(true);
    }
  });

  it("POST /auth/logout — refresh token is revoked after logout", async () => {
    const { refreshCookie } = await loginTestUser(logoutUser);

    await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });

    const refreshRes = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });

    expect(refreshRes.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/logout — rejects request without cookie", async () => {
    const res = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/logout — rejects invalid cookie value", async () => {
    const res = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { Cookie: "refreshToken=invalid.token.here" },
    });

    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("POST /auth/logout — double logout rejects second attempt", async () => {
    const { refreshCookie } = await loginTestUser(logoutUser);

    const first = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });
    expect(first.status).toBe(200);

    const second = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { Cookie: refreshCookie },
    });
    expect(second.status).toBeGreaterThanOrEqual(400);
  });
});

// ─── Full Flow (E2E) ───────────────────────────────────

describe("Auth - Full Flow (E2E)", () => {
  const e2eUser = {
    username: `e2e_user_${uniqueSuffix}`,
    password: "e2ePassword123!",
    email: `e2e_${uniqueSuffix}@test.com`,
  };

  it("register → login (cookie) → me → refresh (cookie) → me → logout (cookie)", async () => {
    const registerRes = await fetch(`${BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(e2eUser),
    });
    expect(registerRes.status).toBe(200);
    const registerData = await registerRes.json();
    expect(registerData.user.username).toBe(e2eUser.username);

    const loginRes = await fetch(`${BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: e2eUser.username,
        password: e2eUser.password,
      }),
    });
    expect(loginRes.status).toBe(200);
    const loginData = await loginRes.json();
    expect(loginData.accessToken).toBeDefined();
    expect(loginData.refreshToken).toBeUndefined();
    const loginCookie = extractCookie(loginRes, "refreshToken");
    expect(loginCookie).not.toBeNull();

    const meRes = await fetch(`${BASE_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${loginData.accessToken}` },
    });
    expect(meRes.status).toBe(200);
    const meData = await meRes.json();
    expect(meData.username).toBe(e2eUser.username);
    expect(meData.email).toBe(e2eUser.email);

    const refreshRes = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: loginCookie! },
    });
    expect(refreshRes.status).toBe(200);
    const refreshData = await refreshRes.json();
    expect(refreshData.accessToken).toBeDefined();
    expect(refreshData.refreshToken).toBeUndefined();
    const refreshedCookie = extractCookie(refreshRes, "refreshToken");
    expect(refreshedCookie).not.toBeNull();

    const meRes2 = await fetch(`${BASE_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${refreshData.accessToken}` },
    });
    expect(meRes2.status).toBe(200);
    const meData2 = await meRes2.json();
    expect(meData2.username).toBe(e2eUser.username);

    const logoutRes = await fetch(`${BASE_URL}/auth/logout`, {
      method: "POST",
      headers: { Cookie: refreshedCookie! },
    });
    expect(logoutRes.status).toBe(200);

    const refreshAfterLogout = await fetch(`${BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { Cookie: refreshedCookie! },
    });
    expect(refreshAfterLogout.status).toBeGreaterThanOrEqual(400);
  });
});
