import jwt from "@elysiajs/jwt";
import Elysia from "elysia";
import { prisma } from "../utils/prisma";
import crypto from "crypto";
import bearer from "@elysiajs/bearer";

export const authService = new Elysia({ name: "auth.service" })
  .use(
    jwt({
      secret: "accesstksecret",
      exp: "5m",
      name: "accessToken",
    }),
  )
  .use(
    jwt({
      secret: "refreshtksecret",
      exp: "7d",
      name: "refreshToken",
    }),
  )
  .use(bearer())
  .derive({ as: "scoped" }, ({ accessToken, refreshToken, status }) => {
    const saveRefreshToken = async (userId: number, plainToken: string) => {
      const hashedToken = crypto
        .createHash("sha256")
        .update(plainToken)
        .digest("hex");
      return await prisma.refreshToken.create({
        data: {
          userId,
          token: hashedToken,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        },
      });
    };

    const findValidRefreshToken = async (plainToken: string) => {
      const hashedToken = crypto
        .createHash("sha256")
        .update(plainToken)
        .digest("hex");
      const token = await prisma.refreshToken.findFirst({
        where: {
          revoked: false,
          expiresAt: {
            gt: new Date(),
          },
          token: hashedToken,
        },
        include: {
          user: true,
        },
      });
      return token;
    };

    const login = async (body: { username: string; password: string }) => {
      const { username, password } = body;
      const user = await prisma.user.findUnique({
        where: { username },
      });
      if (!user) throw status(404, "User not found!");
      const isPasswordValid = await Bun.password.verify(
        password,
        user.password,
      );
      if (!isPasswordValid) throw status(401, "Invalid password!");

      const access_token = await accessToken.sign({
        userId: user.id,
        username: user.username,
        email: user.email,
      });

      const refresh_token = await refreshToken.sign({
        userId: user.id,
        username: user.username,
        email: user.email,
      });

      await saveRefreshToken(user.id, refresh_token);

      return {
        message: "Login successful",
        accessToken: access_token,
        refreshToken: refresh_token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
      };
    };

    const refresh = async (refreshTk: string) => {
      const payload = await refreshToken.verify(refreshTk);
      if (!payload) throw status(404, "Invalid refresh token!");
      const token = await findValidRefreshToken(refreshTk);
      if (!token || token.userId !== payload.userId) throw status(401, "Refresh token not found or expired!");
      const access_token = await accessToken.sign({
        userId: payload.id,
        username: payload.username,
        email: payload.email,
      });

      const refresh_token = await refreshToken.sign({
        userId: payload.id,
        username: payload.username,
        email: payload.email,
      });
      await prisma.refreshToken.update({
        where: { id: token.id },
        data: { revoked: true },
      });
      await saveRefreshToken(payload.userId, refresh_token);
      return {
        accessToken: access_token,
        refreshToken: refresh_token,
      };
    };

    const register = async (body: {
      username: string;
      password: string;
      email: string;
    }) => {
      const { username, password, email } = body;
      const hashedPassword = await Bun.password.hash(password);
      const user = await prisma.user.create({
        data: {
          username,
          password: hashedPassword,
          email,
        },
        select: {
          id: true,
          username: true,
          email: true,
        },
      });
      return {
        message: "User registered successfully",
        user,
      };
    };

    return {
      register,
      login,
      refresh,
    };
  })
  .macro({
    isAuth: {
      resolve: async ({ bearer, status, accessToken }) => {
        if (!bearer) throw status(404, "Token not found!");
        const payload = await accessToken.verify(bearer);
        if (!payload) throw status(401, "Invalid token!");
        const user = await prisma.user.findUnique({
          where: { id: Number(payload.userId) },
          select: {
            id: true,
            username: true,
            email: true,
          },
        });
        if (!user) throw status(404, "User not found!");
        return {
          user
        };
      },
    },
  });
