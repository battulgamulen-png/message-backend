import * as Ably from "ably";
import { ChatClient } from "@ably/chat";
import type { ChatMessageEvent } from "@ably/chat";

async function getStarted() {
  const apiKey = process.env.ABLY_API_KEY;
  if (!apiKey) {
    throw new Error("ABLY_API_KEY environment variable is required");
  }

  const realtimeClient = new Ably.Realtime({
    key: apiKey,
    clientId: "my-first-client",
  });

  const chatClient = new ChatClient(realtimeClient);

  chatClient.connection.onStatusChange((change) =>
    console.log(`Connection status is currently ${change.current}!`),
  );
}

getStarted();
