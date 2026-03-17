"use client";

import { FormEvent, useRef, useState } from "react";
import { Bot, Loader2, Paperclip, SendHorizonal, UserRound } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorMessage } from "@/components/ui/error-message";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { useChatHistory } from "@/components/providers/chat-history-provider";
import { useAuth } from "@/hooks/use-auth";
import { scanFile, sendChat } from "@/lib/api";
import { ChatMessageRecord } from "@/lib/chat-history";
import { errorMessage } from "@/lib/error-utils";
import type { FileScanResponse } from "@/types/api";

const CHAT_UPLOAD_ACCEPT = ".txt,.md,.csv,.json,.pdf,.docx";

function formatFileSize(sizeBytes: number): string {
  const value = Math.max(0, Number(sizeBytes) || 0);
  if (value >= 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (value >= 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${value} B`;
}

function buildPromptWithAttachment(prompt: string, attachmentName: string, scanResult: FileScanResponse): string {
  const userPrompt = prompt.trim() || "Please analyze the attached file and provide a concise response.";
  const extracted = (scanResult.redacted_text || scanResult.extracted_text || "").trim() || "No text could be extracted.";
  const decision = String(scanResult.decision || "ALLOW").toUpperCase();
  const riskLevel = String(scanResult.risk_level || "LOW").toUpperCase();
  const filename = attachmentName || scanResult.filename || "attachment";
  return (
    `${userPrompt}\n\n`
    + "Attached file context:\n"
    + `Filename: ${filename}\n`
    + `Scan decision: ${decision}\n`
    + `Scan risk level: ${riskLevel}\n`
    + "Redacted extracted text:\n"
    + `${extracted}`
  );
}

function buildBlockedAttachmentMessage(scanResult: FileScanResponse): string {
  const reasons = Array.isArray(scanResult.decision_reasons) ? scanResult.decision_reasons.filter(Boolean) : [];
  if (!reasons.length) {
    return "Attachment was blocked by tenant policy and was not sent to the model.";
  }
  return `Attachment was blocked by tenant policy. Reasons: ${reasons.join("; ")}`;
}

export default function ChatPage() {
  const { token } = useAuth();
  const { activeConversation, messages, historyLoading, appendMessage } = useChatHistory();

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [input, setInput] = useState("");
  const [attachment, setAttachment] = useState<File | null>(null);
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);

  const canSend = Boolean((input.trim().length > 0 || attachment) && !sending);

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const prompt = input.trim();
    if ((!prompt && !attachment) || !token || !activeConversation) {
      return;
    }

    setError("");
    setSending(true);
    const pendingAttachment = attachment;
    const chatId = activeConversation.id;
    const userMessage: ChatMessageRecord = {
      id: crypto.randomUUID(),
      role: "user",
      content: prompt || "Sent an attachment.",
      attachments: pendingAttachment
        ? [
          {
            name: pendingAttachment.name,
            sizeBytes: pendingAttachment.size,
          },
        ]
        : undefined,
      createdAt: Date.now(),
    };
    appendMessage(chatId, userMessage);
    setInput("");
    setAttachment(null);

    try {
      let promptToSend = prompt;
      if (pendingAttachment) {
        let scanResult: FileScanResponse;
        try {
          scanResult = await scanFile(token, pendingAttachment, "next_chat_attachment");
        } catch (scanErr) {
          const message = errorMessage(scanErr, "Attachment scan failed.");
          appendMessage(chatId, {
            id: crypto.randomUUID(),
            role: "assistant",
            content: `Attachment scan failed: ${message}`,
            status: "error",
            provider: "file_scan",
            createdAt: Date.now(),
          });
          setError(message);
          return;
        }

        if (scanResult.blocked) {
          appendMessage(chatId, {
            id: crypto.randomUUID(),
            role: "assistant",
            content: buildBlockedAttachmentMessage(scanResult),
            status: "error",
            provider: "file_scan",
            requestId: scanResult.request_id,
            decision: scanResult.decision,
            riskLevel: scanResult.risk_level,
            createdAt: Date.now(),
          });
          return;
        }

        promptToSend = buildPromptWithAttachment(prompt, pendingAttachment.name, scanResult);
      }

      const response = await sendChat(token, {
        prompt: promptToSend,
        purpose: "Next.js Team Chat",
        rehydrate_response: false,
      });
      const assistant: ChatMessageRecord = {
        id: response.request_id || crypto.randomUUID(),
        role: "assistant",
        content: response.assistant_response || response.ai_response_clean || "",
        status: "ok",
        decision: response.decision,
        riskLevel: response.risk_level,
        provider: response.provider,
        model: response.model,
        requestId: response.request_id,
        createdAt: Date.now(),
      };
      appendMessage(chatId, assistant);
    } catch (err) {
      const message = errorMessage(err, "Request failed.");
      const assistant: ChatMessageRecord = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: message,
        status: "error",
        createdAt: Date.now(),
      };
      appendMessage(chatId, assistant);
      setError(message);
    } finally {
      setSending(false);
    }
  };

  if (historyLoading) {
    return <Skeleton className="h-[74vh]" />;
  }

  return (
    <div className="space-y-5">
      <Card className="stagger-item overflow-hidden">
        <CardHeader className="border-b border-slate-200/70 bg-[linear-gradient(180deg,#ffffff_0%,#f7fbff_100%)] pb-5">
          <CardTitle className="text-[1.7rem]">Team Chat</CardTitle>
          <CardDescription className="mt-1">
            Ask questions, upload files, and continue your active conversation.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4 pt-5">
          <div className="rounded-2xl border border-slate-200/90 bg-[linear-gradient(180deg,#f8fbff_0%,#f5f8fd_100%)] p-3 sm:p-4">
            {!activeConversation ? (
              <EmptyState title="No active chat" description="Start a new chat from the sidebar to get started." />
            ) : (
              <>
                <div className="app-scroll max-h-[62vh] space-y-4 overflow-y-auto pr-1.5">
                  {messages.length === 0 ? (
                    <EmptyState
                      title="Start a conversation"
                      description="Ask a question or upload a file to begin chatting with your assistant."
                    />
                  ) : null}

                  {messages.map((message) => {
                    const isUser = message.role === "user";
                    return (
                      <div key={message.id} className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
                        <div className={`max-w-[92%] space-y-1 sm:max-w-[74%] ${isUser ? "text-right" : "text-left"}`}>
                          <p
                            className={`flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] ${
                              isUser ? "justify-end text-cyan-700" : "text-slate-500"
                            }`}
                          >
                            {isUser ? <UserRound className="h-3.5 w-3.5" /> : <Bot className="h-3.5 w-3.5" />}
                            {isUser ? "You" : "Assistant"}
                          </p>
                          <div
                            className={`rounded-2xl px-4 py-3 text-sm shadow-sm ${
                              isUser
                                ? "bg-[linear-gradient(145deg,#0891b2_0%,#0e7490_100%)] text-primary-foreground shadow-[0_10px_28px_rgba(8,145,178,0.25)]"
                                : message.status === "error"
                                  ? "border border-rose-200 bg-rose-50 text-rose-800"
                                  : "border border-slate-200/90 bg-white text-slate-800"
                            }`}
                          >
                            <p className="whitespace-pre-wrap leading-relaxed">{message.content}</p>

                            {isUser && message.attachments?.length ? (
                              <div className="mt-2 space-y-1 text-[11px]">
                                {message.attachments.map((item) => (
                                  <p
                                    key={`${message.id}:${item.name}`}
                                    className="inline-flex items-center gap-1.5 rounded-full bg-white/20 px-2 py-1"
                                  >
                                    <Paperclip className="h-3 w-3" />
                                    {item.name} ({formatFileSize(item.sizeBytes)})
                                  </p>
                                ))}
                              </div>
                            ) : null}

                          </div>
                        </div>
                      </div>
                    );
                  })}

                  {sending ? (
                    <div className="flex justify-start">
                      <div className="inline-flex items-center gap-2 rounded-2xl border border-slate-200/90 bg-white px-4 py-3 text-sm text-slate-600 shadow-sm">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Generating response...
                      </div>
                    </div>
                  ) : null}
                </div>

                <form
                  onSubmit={onSubmit}
                  className="mt-4 rounded-2xl border border-slate-200/95 bg-white p-2.5 shadow-[0_8px_24px_rgba(15,23,42,0.08)]"
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept={CHAT_UPLOAD_ACCEPT}
                    className="hidden"
                    onChange={(event) => {
                      const file = event.target.files?.[0] ?? null;
                      setAttachment(file);
                    }}
                  />

                  {attachment ? (
                    <div className="mb-2 flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
                      <div className="inline-flex items-center gap-1.5">
                        <Paperclip className="h-3.5 w-3.5 text-slate-500" />
                        <span>
                          {attachment.name} ({formatFileSize(attachment.size)})
                        </span>
                      </div>
                      <button
                        type="button"
                        className="font-semibold text-slate-500 hover:text-slate-700"
                        onClick={() => {
                          setAttachment(null);
                          if (fileInputRef.current) {
                            fileInputRef.current.value = "";
                          }
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  ) : null}

                  <div className="flex items-end gap-2">
                    <Button
                      type="button"
                      size="md"
                      variant="secondary"
                      className="w-10 shrink-0 px-0"
                      onClick={() => fileInputRef.current?.click()}
                      title="Upload file"
                    >
                      <Paperclip className="h-4 w-4" />
                    </Button>
                    <Textarea
                      value={input}
                      onChange={(event) => setInput(event.target.value)}
                      placeholder="Message Shadow Gateway..."
                      className="min-h-[60px] resize-none border-0 bg-transparent shadow-none focus:ring-0"
                    />
                    <Button type="submit" size="md" disabled={!canSend} className="shrink-0">
                      {sending ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <SendHorizonal className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </form>
              </>
            )}
          </div>

          {error ? <ErrorMessage message={error} /> : null}
        </CardContent>
      </Card>
    </div>
  );
}
