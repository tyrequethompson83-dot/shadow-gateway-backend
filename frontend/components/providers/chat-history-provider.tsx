"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { useAuth } from "@/hooks/use-auth";
import { ChatConversationRecord, ChatMessageRecord, loadChatHistory, saveChatHistory } from "@/lib/chat-history";

type ChatHistoryContextValue = {
  conversations: ChatConversationRecord[];
  activeConversationId: string;
  activeConversation: ChatConversationRecord | null;
  messages: ChatMessageRecord[];
  historyLoading: boolean;
  setActiveConversationId: (conversationId: string) => void;
  startNewChat: () => string;
  deleteConversation: (conversationId: string) => void;
  appendMessage: (conversationId: string, message: ChatMessageRecord) => void;
};

const ChatHistoryContext = createContext<ChatHistoryContextValue | null>(null);

function createConversation(): ChatConversationRecord {
  const now = Date.now();
  return {
    id: crypto.randomUUID(),
    title: "New chat",
    createdAt: now,
    updatedAt: now,
    messages: [],
  };
}

function conversationTitle(messages: ChatMessageRecord[]): string {
  const firstUser = messages.find((item) => item.role === "user");
  if (!firstUser) {
    return "New chat";
  }
  if (
    firstUser.content.trim().toLowerCase() === "sent an attachment."
    && Array.isArray(firstUser.attachments)
    && firstUser.attachments.length
  ) {
    return `Attachment: ${firstUser.attachments[0].name}`;
  }
  const compact = firstUser.content.replace(/\s+/g, " ").trim();
  if (!compact) {
    return "New chat";
  }
  return compact.length > 56 ? `${compact.slice(0, 56)}...` : compact;
}

export function ChatHistoryProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const userId = user?.user_id ?? null;
  const tenantId = user?.tenant_id ?? null;

  const [conversations, setConversations] = useState<ChatConversationRecord[]>([]);
  const [activeConversationId, setActiveConversationIdState] = useState("");
  const [historyLoading, setHistoryLoading] = useState(true);

  useEffect(() => {
    setHistoryLoading(true);
    if (!userId || !tenantId) {
      setConversations([]);
      setActiveConversationIdState("");
      setHistoryLoading(false);
      return;
    }

    const loaded = loadChatHistory(userId, tenantId);
    if (!loaded.length) {
      const starter = createConversation();
      setConversations([starter]);
      setActiveConversationIdState(starter.id);
      setHistoryLoading(false);
      return;
    }

    setConversations(loaded);
    setActiveConversationIdState((current) =>
      current && loaded.some((conversation) => conversation.id === current) ? current : loaded[0].id,
    );
    setHistoryLoading(false);
  }, [userId, tenantId]);

  useEffect(() => {
    if (!conversations.length) {
      if (activeConversationId) {
        setActiveConversationIdState("");
      }
      return;
    }
    if (!activeConversationId || !conversations.some((conversation) => conversation.id === activeConversationId)) {
      setActiveConversationIdState(conversations[0].id);
    }
  }, [conversations, activeConversationId]);

  useEffect(() => {
    if (!userId || !tenantId || historyLoading) {
      return;
    }
    saveChatHistory(userId, tenantId, conversations);
  }, [conversations, userId, tenantId, historyLoading]);

  const setActiveConversationId = useCallback((conversationId: string) => {
    setActiveConversationIdState(conversationId);
  }, []);

  const startNewChat = useCallback(() => {
    const created = createConversation();
    setConversations((prev) => [created, ...prev].sort((a, b) => b.updatedAt - a.updatedAt));
    setActiveConversationIdState(created.id);
    return created.id;
  }, []);

  const deleteConversation = useCallback(
    (conversationId: string) => {
      const target = String(conversationId || "");
      if (!target) {
        return;
      }

      setConversations((prev) => prev.filter((conversation) => conversation.id !== target));
      setActiveConversationIdState((current) => (current === target ? "" : current));
    },
    [],
  );

  const appendMessage = useCallback((conversationId: string, message: ChatMessageRecord) => {
    setConversations((prev) => {
      let found = false;
      const next = prev
        .map((conversation) => {
          if (conversation.id !== conversationId) {
            return conversation;
          }
          found = true;
          const updatedMessages = [...conversation.messages, message];
          return {
            ...conversation,
            messages: updatedMessages,
            title: conversationTitle(updatedMessages),
            updatedAt: Date.now(),
          };
        })
        .sort((a, b) => b.updatedAt - a.updatedAt);
      if (!found) {
        return prev;
      }
      return next;
    });
  }, []);

  const activeConversation = useMemo(
    () => conversations.find((conversation) => conversation.id === activeConversationId) || null,
    [conversations, activeConversationId],
  );

  const messages = useMemo(() => activeConversation?.messages ?? [], [activeConversation]);

  const value = useMemo<ChatHistoryContextValue>(
    () => ({
      conversations,
      activeConversationId,
      activeConversation,
      messages,
      historyLoading,
      setActiveConversationId,
      startNewChat,
      deleteConversation,
      appendMessage,
    }),
    [
      conversations,
      activeConversationId,
      activeConversation,
      messages,
      historyLoading,
      setActiveConversationId,
      startNewChat,
      deleteConversation,
      appendMessage,
    ],
  );

  return <ChatHistoryContext.Provider value={value}>{children}</ChatHistoryContext.Provider>;
}

export function useChatHistory(): ChatHistoryContextValue {
  const value = useContext(ChatHistoryContext);
  if (!value) {
    throw new Error("useChatHistory must be used inside ChatHistoryProvider");
  }
  return value;
}
