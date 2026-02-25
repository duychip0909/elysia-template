import cors from "@elysiajs/cors";
import openapi from "@elysiajs/openapi";
import { Elysia } from "elysia";
import { authController } from "./controllers/auth";
import cron, { Patterns } from "@elysiajs/cron";
import { prisma } from "./utils/prisma";

const app = new Elysia()
  .use(cors({
    credentials: true,
    origin: Bun.env.FRONTEND_URL || "http://localhost:5173"
  }))
  .use(openapi({
    documentation: {
      info: {
        title: "Duychip Elysia Template",
        description: "A template for Elysia projects",
        version: "1.0.0"
      }
    }
  }))
  .get("/health", () => ({ status: "ok", timestamp: new Date() }))
  .use(cron({
    name: "clear expired tokens",
    pattern: Patterns.EVERY_10_MINUTES,
    async run() {
      try {
        const result = await prisma.refreshToken.deleteMany({
          where: {
            OR: [
              { expiresAt: { lt: new Date() } },
              { revoked: true },
            ],
          },
        });

        if (result.count > 0) {
          console.log(`[cron] Cleared ${result.count} expired/revoked token(s)`);
        }
      } catch (error) {
        console.error("[cron] Failed to clear expired tokens:", error);
      }
    }
  }))
  .use(authController)
  .listen({
    port: Bun.env.PORT || 3000,
    hostname: "0.0.0.0"
  });

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
