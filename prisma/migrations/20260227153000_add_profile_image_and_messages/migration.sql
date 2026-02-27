ALTER TABLE "users"
ADD COLUMN "profile_image" TEXT;

CREATE TABLE "messages" (
  "id" UUID NOT NULL,
  "user_id" UUID NOT NULL,
  "text" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "messages_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "messages_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "messages_user_id_created_at_idx" ON "messages"("user_id", "created_at");
