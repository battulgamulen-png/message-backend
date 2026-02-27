const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const Ably = require("ably");
const { Pool } = require("pg");
const { PrismaPg } = require("@prisma/adapter-pg");
const { PrismaClient } = require("./prisma/generated");

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const sep = line.indexOf("=");
    if (sep === -1) {
      continue;
    }

    const key = line.slice(0, sep).trim();
    let value = line.slice(sep + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

const root = __dirname;
loadEnvFile(path.join(root, ".env"));
loadEnvFile(path.join(root, ".env.local"));

const port = Number(process.env.PORT || 4000);
const databaseUrl = process.env.DATABASE_URL || "";
const shouldUseSslForSupabase =
  databaseUrl.includes("supabase.com") && !databaseUrl.includes("sslmode=disable");

const pool = new Pool({
  connectionString: databaseUrl,
  ...(shouldUseSslForSupabase ? { ssl: { rejectUnauthorized: false } } : {}),
});
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });
const authSecret = process.env.AUTH_SECRET || "dev-secret-change-me";
const ablyApiKey = process.env.ABLY_API_KEY || "";
const ablyRest = ablyApiKey ? new Ably.Rest(ablyApiKey) : null;

function getAblyChannelName(userId) {
  return `chat:${userId}`;
}

function resolveErrorResponse(error) {
  const code = typeof error?.code === "string" ? error.code : "";

  if (code === "P1001") {
    return { status: 503, message: "Database холболт амжилтгүй. DATABASE_URL-ээ шалгана уу." };
  }

  if (code === "P2021" || code === "P2022") {
    return {
      status: 500,
      message: "Database schema зөрсөн байна. `npx prisma migrate deploy` ажиллуулна уу.",
    };
  }

  if (code === "P2010") {
    return {
      status: 500,
      message: "Database query алдаа гарлаа. DB холболт болон schema-гаа шалгана уу.",
    };
  }

  return { status: 500, message: "Дотоод серверийн алдаа." };
}

function toBase64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64Url(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padLength), "base64").toString("utf8");
}

function signToken(payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = toBase64Url(JSON.stringify(header));
  const encodedPayload = toBase64Url(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac("sha256", authSecret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signature}`;
}

function verifyToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [encodedHeader, encodedPayload, providedSignature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto
    .createHmac("sha256", authSecret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (expectedSignature !== providedSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(fromBase64Url(encodedPayload));
    if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function getAuthPayload(req) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : "";
  return token ? verifyToken(token) : null;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash) {
    return false;
  }

  const [salt, originalHash] = storedHash.split(":");
  if (!salt || !originalHash) {
    return false;
  }

  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(originalHash, "hex"));
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  });
  res.end(JSON.stringify(payload));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 6_000_000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });

    req.on("error", reject);
  });
}

async function handleSignUp(req, res) {
  const body = await readJsonBody(req);
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const fullName = typeof body.fullName === "string" ? body.fullName.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!email || !password) {
    sendJson(res, 400, { message: "Email болон password шаардлагатай." });
    return;
  }

  if (password.length < 8) {
    sendJson(res, 400, { message: "Password дор хаяж 8 тэмдэгттэй байна." });
    return;
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    sendJson(res, 409, { message: "Энэ email аль хэдийн бүртгэлтэй байна." });
    return;
  }

  const user = await prisma.user.create({
    data: {
      email,
      fullName: fullName || null,
      passwordHash: hashPassword(password),
    },
    select: {
      id: true,
      email: true,
      fullName: true,
      profileImage: true,
      createdAt: true,
    },
  });

  const token = signToken({
    sub: user.id,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
  });

  sendJson(res, 201, { user, token });
}

async function handleLogin(req, res) {
  const body = await readJsonBody(req);
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!email || !password) {
    sendJson(res, 400, { message: "Email болон password шаардлагатай." });
    return;
  }

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      fullName: true,
      profileImage: true,
      passwordHash: true,
    },
  });

  if (!user || !verifyPassword(password, user.passwordHash)) {
    sendJson(res, 401, { message: "Email эсвэл password буруу байна." });
    return;
  }

  const token = signToken({
    sub: user.id,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
  });

  sendJson(res, 200, {
    user: {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      profileImage: user.profileImage,
    },
    token,
  });
}

async function handleMe(req, res) {
  const payload = getAuthPayload(req);

  if (!payload?.sub) {
    sendJson(res, 401, { message: "Нэвтрэлт шаардлагатай." });
    return;
  }

  const user = await prisma.user.findUnique({
    where: { id: payload.sub },
    select: {
      id: true,
      email: true,
      fullName: true,
      profileImage: true,
      createdAt: true,
    },
  });

  if (!user) {
    sendJson(res, 401, { message: "Хэрэглэгч олдсонгүй." });
    return;
  }

  sendJson(res, 200, { user });
}

async function handleUpdateProfile(req, res) {
  const payload = getAuthPayload(req);
  if (!payload?.sub) {
    sendJson(res, 401, { message: "Нэвтрэлт шаардлагатай." });
    return;
  }

  const body = await readJsonBody(req);
  const fullName =
    typeof body.fullName === "string" ? body.fullName.trim() : undefined;
  const profileImage =
    typeof body.profileImage === "string"
      ? body.profileImage.trim()
      : body.profileImage === null
        ? null
        : undefined;

  if (profileImage && profileImage.length > 5_000_000) {
    sendJson(res, 400, { message: "Зургийн хэмжээ хэтэрсэн байна." });
    return;
  }

  const user = await prisma.user.update({
    where: { id: payload.sub },
    data: {
      ...(fullName !== undefined ? { fullName: fullName || null } : {}),
      ...(profileImage !== undefined ? { profileImage: profileImage || null } : {}),
    },
    select: {
      id: true,
      email: true,
      fullName: true,
      profileImage: true,
      createdAt: true,
    },
  });

  sendJson(res, 200, { user });
}

async function handleGetMessages(req, res) {
  const payload = getAuthPayload(req);
  if (!payload?.sub) {
    sendJson(res, 401, { message: "Нэвтрэлт шаардлагатай." });
    return;
  }

  const messages = await prisma.message.findMany({
    where: { userId: payload.sub },
    orderBy: { createdAt: "asc" },
    select: {
      id: true,
      text: true,
      createdAt: true,
    },
  });

  sendJson(res, 200, { messages });
}

async function handleCreateMessage(req, res) {
  const payload = getAuthPayload(req);
  if (!payload?.sub) {
    sendJson(res, 401, { message: "Нэвтрэлт шаардлагатай." });
    return;
  }

  const body = await readJsonBody(req);
  const text = typeof body.text === "string" ? body.text.trim() : "";

  if (!text) {
    sendJson(res, 400, { message: "Мессеж хоосон байж болохгүй." });
    return;
  }

  const message = await prisma.message.create({
    data: {
      userId: payload.sub,
      text,
    },
    select: {
      id: true,
      text: true,
      createdAt: true,
    },
  });

  if (ablyRest) {
    try {
      const channel = ablyRest.channels.get(getAblyChannelName(payload.sub));
      await channel.publish("message.created", { message });
    } catch (error) {
      console.error("Ably publish failed:", error);
    }
  }

  sendJson(res, 201, { message });
}

async function handleAblyToken(req, res) {
  const payload = getAuthPayload(req);
  if (!payload?.sub) {
    sendJson(res, 401, { message: "Нэвтрэлт шаардлагатай." });
    return;
  }

  if (!ablyRest) {
    sendJson(res, 500, { message: "ABLY_API_KEY тохируулаагүй байна." });
    return;
  }

  const channelName = getAblyChannelName(payload.sub);
  const tokenRequest = await ablyRest.auth.createTokenRequest({
    clientId: payload.sub,
    capability: JSON.stringify({
      [channelName]: ["subscribe", "publish"],
    }),
    ttl: 1000 * 60 * 60,
  });

  sendJson(res, 200, tokenRequest);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") {
      sendJson(res, 204, {});
      return;
    }

    if (req.url === "/health") {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === "POST" && req.url === "/auth/signup") {
      await handleSignUp(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/auth/login") {
      await handleLogin(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/auth/me") {
      await handleMe(req, res);
      return;
    }

    if (req.method === "PUT" && req.url === "/auth/profile") {
      await handleUpdateProfile(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/chats/messages") {
      await handleGetMessages(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/chats/messages") {
      await handleCreateMessage(req, res);
      return;
    }

    if (req.method === "GET" && req.url?.startsWith("/ably/token")) {
      await handleAblyToken(req, res);
      return;
    }

    sendJson(res, 200, {
      message: "Backend is running",
      port,
    });
  } catch (error) {
    console.error(error);
    const resolved = resolveErrorResponse(error);
    sendJson(res, resolved.status, { message: resolved.message });
  }
});

server.listen(port, () => {
  console.log(`Backend listening on http://localhost:${port}`);
});

process.on("SIGINT", async () => {
  await prisma.$disconnect();
  await pool.end();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await prisma.$disconnect();
  await pool.end();
  process.exit(0);
});

module.exports = server;
