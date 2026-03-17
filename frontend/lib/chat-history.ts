export type ChatAttachment = {
  name: string;
  sizeBytes: number;
};

export type ChatMessageRecord = {
  id: string;
  role: "user" | "assistant";
  content: string;
  status?: "ok" | "error";
  decision?: string;
  riskLevel?: string;
  provider?: string;
  model?: string;
  requestId?: string;
  attachments?: ChatAttachment[];
  createdAt: number;
};

export type ChatConversationRecord = {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messages: ChatMessageRecord[];
};

const STORAGE_PREFIX = "shadow_gateway_chat_history_v1";
const MAX_CONVERSATIONS = 25;

function storageKey(userId: number, tenantId: number): string {
  return `${STORAGE_PREFIX}:${userId}:${tenantId}`;
}

function safeArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export function loadChatHistory(userId: number, tenantId: number): ChatConversationRecord[] {
  if (typeof window === "undefined") {
    return [];
  }
  try {
    const raw = window.localStorage.getItem(storageKey(userId, tenantId));
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    const rows = safeArray<ChatConversationRecord>(parsed);
    return rows
      .filter((row) => row && typeof row.id === "string")
      .map((row) => ({
        id: String(row.id),
        title: String(row.title || "New chat"),
        createdAt: Number(row.createdAt || Date.now()),
        updatedAt: Number(row.updatedAt || Date.now()),
        messages: safeArray<ChatMessageRecord>(row.messages).map((message) => {
          const role: ChatMessageRecord["role"] = message.role === "assistant" ? "assistant" : "user";
          const status: ChatMessageRecord["status"] =
            message.status === "error" ? "error" : message.status === "ok" ? "ok" : undefined;
          return {
            id: String(message.id || crypto.randomUUID()),
            role,
            content: String(message.content || ""),
            status,
            decision: message.decision ? String(message.decision) : undefined,
            riskLevel: message.riskLevel ? String(message.riskLevel) : undefined,
            provider: message.provider ? String(message.provider) : undefined,
            model: message.model ? String(message.model) : undefined,
            requestId: message.requestId ? String(message.requestId) : undefined,
            attachments: safeArray<ChatAttachment>(message.attachments).map((attachment) => ({
              name: String(attachment.name || "attachment"),
              sizeBytes: Number(attachment.sizeBytes || 0),
            })),
            createdAt: Number(message.createdAt || Date.now()),
          };
        }),
      }))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, MAX_CONVERSATIONS);
  } catch {
    return [];
  }
}

export function saveChatHistory(userId: number, tenantId: number, conversations: ChatConversationRecord[]): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    const trimmed = conversations
      .slice()
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, MAX_CONVERSATIONS);
    window.localStorage.setItem(storageKey(userId, tenantId), JSON.stringify(trimmed));
  } catch {
    // best effort local persistence
  }
}
