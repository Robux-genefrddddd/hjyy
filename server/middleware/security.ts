import { Request, Response, NextFunction } from "express";
import { z } from "zod";

/**
 * Content-Type validation middleware.
 * Ensures requests have valid content types.
 */
export function validateContentType(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const contentType = req.get("content-type");

  // Allow JSON requests
  if (req.method === "POST" || req.method === "PUT") {
    if (!contentType?.includes("application/json")) {
      return res.status(400).json({
        error: "Invalid Content-Type. Must be application/json.",
      });
    }
  }

  next();
}

/**
 * Request body size limit to prevent buffer overflow attacks.
 */
export function validateRequestSize(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const maxSize = 10 * 1024 * 1024; // 10MB

  if (req.headers["content-length"]) {
    const contentLength = parseInt(req.headers["content-length"]);
    if (contentLength > maxSize) {
      return res.status(413).json({
        error: "Request body too large.",
      });
    }
  }

  next();
}

/**
 * Input validation middleware.
 * Checks request body for suspicious patterns and injection attempts.
 */
export function validateInput(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (!req.body || typeof req.body !== "object") {
    return next();
  }

  // Check for null bytes in all string values
  const hasNullBytes = (obj: unknown): boolean => {
    if (typeof obj === "string") {
      return obj.includes("\0");
    }
    if (typeof obj === "object" && obj !== null) {
      return Object.values(obj).some(hasNullBytes);
    }
    return false;
  };

  if (hasNullBytes(req.body)) {
    return res.status(400).json({
      error: "Invalid input: null bytes detected.",
    });
  }

  // Check for excessively long strings (prevent DoS)
  const checkStringLength = (obj: unknown, maxLength = 10000): boolean => {
    if (typeof obj === "string" && obj.length > maxLength) {
      return true;
    }
    if (typeof obj === "object" && obj !== null) {
      return Object.values(obj).some((val) => checkStringLength(val, maxLength));
    }
    return false;
  };

  if (checkStringLength(req.body)) {
    return res.status(400).json({
      error: "Invalid input: string too long.",
    });
  }

  // Detect common injection patterns
  const suspiciousPatterns = [
    /<script[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /SELECT|INSERT|UPDATE|DELETE|DROP/i,
    /UNION|WHERE/i,
    /\.\.\/|\.\.\\/,
  ];

  const hasSuspiciousContent = (obj: unknown): boolean => {
    if (typeof obj === "string") {
      return suspiciousPatterns.some((pattern) => pattern.test(obj));
    }
    if (typeof obj === "object" && obj !== null) {
      return Object.values(obj).some(hasSuspiciousContent);
    }
    return false;
  };

  // Only warn, don't block (some legitimate content may contain these words)
  if (hasSuspiciousContent(req.body)) {
    console.warn(
      `[SECURITY] Potentially suspicious content detected in ${req.method} ${req.path}`,
    );
  }

  next();
}

/**
 * Rate limiting helper using in-memory store.
 * For production, use Redis or similar.
 */
const rateLimitStore = new Map<
  string,
  { count: number; resetTime: number }
>();

export function rateLimit(
  windowMs: number = 60000,
  maxRequests: number = 100,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip =
      (req.headers["x-forwarded-for"] as string) ||
      req.ip ||
      req.socket.remoteAddress ||
      "unknown";

    const key = `${ip}:${req.path}`;
    const now = Date.now();

    const record = rateLimitStore.get(key);

    if (!record || now > record.resetTime) {
      // New window
      rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (record.count >= maxRequests) {
      return res.status(429).json({
        error: "Too many requests. Please try again later.",
        retryAfter: Math.ceil((record.resetTime - now) / 1000),
      });
    }

    record.count++;
    next();
  };
}

/**
 * CORS origin validation.
 * Restricts requests to allowed origins.
 */
export function validateOrigin(allowedOrigins: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;

    if (!origin || !allowedOrigins.includes(origin)) {
      // Log potential CSRF attempt
      console.warn(
        `[SECURITY] Blocked request from unauthorized origin: ${origin}`,
      );
      return res.status(403).json({
        error: "Forbidden: Invalid origin.",
      });
    }

    next();
  };
}

/**
 * ID Token validation schema.
 * Ensures ID tokens follow expected format.
 */
export const IdTokenSchema = z
  .string()
  .min(10, "Token too short")
  .max(3000, "Token too long")
  .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format");

/**
 * Generic input validation using Zod.
 */
export function validateRequestBody<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const validated = schema.parse(req.body);
      req.body = validated;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "Invalid request body",
          details: error.errors,
        });
      }
      res.status(400).json({
        error: "Invalid request body",
      });
    }
  };
}

/**
 * SQL injection detection (for defense-in-depth).
 * Detects common SQL injection patterns.
 */
export function detectSqlInjection(value: string): boolean {
  if (!value || typeof value !== "string") return false;

  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i,
    /(\bunion\b)/i,
    /(--|#|\/\*)/,
    /(\bor\b.*=.*)/i,
    /(\band\b.*=.*)/i,
    /(\bwhere\b)/i,
    /(;)/,
  ];

  return sqlPatterns.some((pattern) => pattern.test(value));
}

/**
 * NoSQL injection detection.
 * Detects common NoSQL injection patterns.
 */
export function detectNoSqlInjection(value: unknown): boolean {
  if (typeof value === "string") {
    // Check for NoSQL operators
    const noSqlPatterns = [
      /\$where/,
      /\$ne/,
      /\$gt/,
      /\$regex/,
      /\$where/,
      /function/i,
    ];
    return noSqlPatterns.some((pattern) => pattern.test(value));
  }

  // Check for object-based injection (e.g., { $ne: null })
  if (typeof value === "object" && value !== null) {
    const keys = Object.keys(value);
    return keys.some((key) => key.startsWith("$"));
  }

  return false;
}

/**
 * Strict input validation for admin operations.
 */
export const AdminOperationSchema = z.object({
  idToken: z
    .string()
    .min(10)
    .max(3000)
    .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format"),
});

export const BanUserSchema = AdminOperationSchema.extend({
  userId: z.string().min(10).max(100),
  reason: z.string().min(5).max(500).trim(),
  duration: z.number().int().min(1).max(36500),
});

export const CreateLicenseSchema = AdminOperationSchema.extend({
  plan: z.enum(["Free", "Classic", "Pro"]),
  validityDays: z.number().int().min(1).max(3650),
});

export const BanIPSchema = AdminOperationSchema.extend({
  ipAddress: z.string().ip({ version: "v4" }).or(z.string().ip({ version: "v6" })),
  reason: z.string().min(5).max(500).trim(),
  duration: z.number().int().min(1).max(36500),
});

export const AddMessageSchema = z.object({
  conversationId: z.string().min(1).max(255),
  userId: z.string().min(10).max(100),
  text: z.string().min(1).max(5000).trim(),
});
