import "dotenv/config";
import express from "express";
import cors from "cors";
import { handleDemo } from "./routes/demo";
import { handleGetIP, handleCheckVPN } from "./routes/ip-detection";
import { handleActivateLicense } from "./routes/license";
import { handleDailyReset } from "./routes/daily-reset";
import { handleAIChat } from "./routes/ai";
import {
  handleVerifyAdmin,
  handleBanUser,
  handleGetAllUsers,
  handleCreateLicense,
  handleBanIP,
  handleDeleteUser,
} from "./routes/admin";
import {
  validateContentType,
  validateRequestSize,
  validateInput,
  rateLimit,
} from "./middleware/security";

export function createServer() {
  const app = express();

  // Trust proxy (for rate limiting to work correctly)
  app.set("trust proxy", 1);

  // Middleware - Order matters!
  // 1. CORS first (allow trusted origins)
  const corsOrigins = (process.env.CORS_ORIGINS || "").split(",").filter(Boolean);
  app.use(
    cors({
      origin: corsOrigins.length > 0 ? corsOrigins : true,
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
    }),
  );

  // 2. Security headers
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("X-Content-Security-Policy", "default-src 'self'");
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    next();
  });

  // 3. Request size validation
  app.use(validateRequestSize);

  // 4. Parse JSON
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  // 5. Content-Type validation
  app.use(validateContentType);

  // 6. Input validation (check for suspicious patterns)
  app.use(validateInput);

  // 7. Rate limiting (general limit, stricter on admin routes)
  app.use(rateLimit(60000, 100)); // 100 requests per minute per IP

  // Example API routes
  app.get("/api/ping", (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? "ping";
    res.json({ message: ping });
  });

  app.get("/api/demo", handleDemo);

  // IP detection routes
  app.get("/api/get-ip", handleGetIP);
  app.post("/api/check-vpn", handleCheckVPN);

  // License activation route
  app.post("/api/activate-license", handleActivateLicense);

  // Daily reset route
  app.post("/api/daily-reset", handleDailyReset);

  // AI chat route
  app.post("/api/ai/chat", handleAIChat);

  // Admin routes (require authentication + stricter rate limiting)
  const adminRateLimit = rateLimit(60000, 10); // 10 requests per minute per IP
  app.post("/api/admin/verify", adminRateLimit, handleVerifyAdmin);
  app.post("/api/admin/ban-user", adminRateLimit, handleBanUser);
  app.post("/api/admin/ban-ip", adminRateLimit, handleBanIP);
  app.post("/api/admin/delete-user", adminRateLimit, handleDeleteUser);
  app.get("/api/admin/users", adminRateLimit, handleGetAllUsers);
  app.post("/api/admin/create-license", adminRateLimit, handleCreateLicense);

  // 404 handler
  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // Error handler
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      console.error("Unhandled error:", err);
      res.status(500).json({ error: "Internal server error" });
    },
  );

  return app;
}
