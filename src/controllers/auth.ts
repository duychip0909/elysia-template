import Elysia, { t } from "elysia";
import { authService } from "../services/auth.service";

export const authController = new Elysia({ prefix: "/auth", tags: ["auth"] })
  .use(authService)
  .get(
    "/me",
    ({ user }) => {
      return user;
    },
    {
      isAuth: true,
    },
  )
  .post(
    "/login",
    async ({ login, body, cookie: { refreshToken: rtCookie } }) => {
      const result = await login(body);
      rtCookie.set({
        value: result.refreshToken,
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: "/auth",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return {
        message: result.message,
        accessToken: result.accessToken,
        user: result.user
      }
    },
    {
      body: t.Object({
        username: t.String({ minLength: 3, maxLength: 32 }),
        password: t.String({ minLength: 8, maxLength: 128 }),
      }),
    },
  )
  .post(
    "/register",
    ({ register, body }) => {
      return register(body);
    },
    {
      body: t.Object({
        username: t.String({ minLength: 3, maxLength: 32 }),
        password: t.String({ minLength: 8, maxLength: 128 }),
        email: t.String({ format: "email", maxLength: 255 }),
      }),
    },
  )
  .post(
    "/refresh",
    async ({ refresh, cookie: { refreshToken: rtCookie }, status }) => {
      const tokenValue= rtCookie.value;
      if (!tokenValue) throw status(401, "No refresh token");
      const result = await refresh(tokenValue);
      rtCookie.set({
        value: result.refreshToken,
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: "/auth",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return {
        accessToken: result.accessToken,
      }
    },
    {
      cookie: t.Object({
        refreshToken: t.String(),
      }),
    }
  )
  .post(
    "/logout",
    async ({ logout, cookie: { refreshToken: rtCookie }, status }) => {
      const tokenValue= rtCookie.value;
      if (!tokenValue) throw status(401, "No refresh token");
      const result = await logout(tokenValue);
      rtCookie.remove();
      return result;
    },
    {
      cookie: t.Object({
        refreshToken: t.String(),
      }),
    },
  );
