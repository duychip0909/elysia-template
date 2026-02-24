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
    ({ login, body }) => {
      return login(body);
    },
    {
      body: t.Object({
        username: t.String(),
        password: t.String(),
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
        username: t.String(),
        password: t.String(),
        email: t.String({ format: "email" }),
      }),
    },
  )
  .post(
    "/refresh",
    ({ refresh, body }) => {
      return refresh(body.refreshToken);
    },
    {
      body: t.Object({
        refreshToken: t.String(),
      }),
    },
  );
