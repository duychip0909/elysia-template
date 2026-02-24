import cors from "@elysiajs/cors";
import openapi from "@elysiajs/openapi";
import { Elysia } from "elysia";
import { authController } from "./controllers/auth";

const app = new Elysia()
  .use(cors())
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
  .use(authController)
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
