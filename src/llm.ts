// Answer path. Two labelled modes:
//   retrieval-only: the answer is assembled from retrieved memories. No network, no keys.
//   model: the memory block goes to NVIDIA Nemotron through the local Meterless
//     Nightshift endpoint (OpenAI-compatible). Switched on by MODEL_BASE_URL + MODEL_API_KEY.
//
// Settings are read from the environment. If they are not set, this file looks for a
// .env in (1) ENV_FILE, (2) the agent-starter folder, (3) ../open-agent-hack/.env.
// Keys are never printed or logged.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface AnswerMeta {
  model: string;
  tokensIn?: number;
  tokensOut?: number;
  latencyMs: number;
  route: string;
}

export interface AnswerResult {
  mode: "retrieval-only" | "model";
  text: string;
  meta?: AnswerMeta;
}

const here = path.dirname(fileURLToPath(import.meta.url));
let envLoaded = false;

function loadEnv(): void {
  if (envLoaded) return;
  envLoaded = true;
  const candidates = [
    process.env.ENV_FILE,
    path.join(here, "..", ".env"),
    path.join(here, "..", "..", "..", "open-agent-hack", ".env"),
  ].filter(Boolean) as string[];
  for (const file of candidates) {
    try {
      if (fs.existsSync(file)) {
        process.loadEnvFile(file); // does not override variables that are already set
        return;
      }
    } catch {
      // ignore an unreadable .env and fall back to retrieval-only
    }
  }
}

export async function answer(
  question: string,
  memoryContext: string,
  memories: { relevance: number; content: string }[],
): Promise<AnswerResult> {
  loadEnv();
  const baseUrl = process.env.MODEL_BASE_URL;
  const apiKey = process.env.MODEL_API_KEY;
  if (!baseUrl || !apiKey || memories.length === 0) {
    return { mode: "retrieval-only", text: retrievalOnly(question, memories) };
  }

  const model = process.env.NEMOTRON_MODEL || "meterless/auto";
  const route = (process.env.MODEL_ROUTE || "direct").toLowerCase();
  const headers: Record<string, string> = {
    "content-type": "application/json",
    authorization: `Bearer ${apiKey}`,
  };
  if (route === "meterless") {
    headers["meterless-app"] = "agent-starter";
    headers["meterless-scope"] = "user";
  }

  const started = Date.now();
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      headers,
      signal: AbortSignal.timeout(60_000),
      body: JSON.stringify({
        model,
        temperature: 0.2,
        max_tokens: 400,
        messages: [
          {
            role: "system",
            content:
              "You answer questions using ONLY the memory context provided. Cite memory ids inline in square brackets, for example [mem-3]. If the memory does not answer the question, say so.",
          },
          { role: "user", content: `${memoryContext}\n\nQuestion: ${question}` },
        ],
      }),
    });
    if (!res.ok) {
      const detail = (await res.text()).slice(0, 200);
      throw new Error(`model endpoint returned ${res.status}: ${detail}`);
    }
    const json: any = await res.json();
    const text: string = json?.choices?.[0]?.message?.content?.trim() ?? "";
    if (!text) throw new Error("model endpoint returned an empty answer");
    return {
      mode: "model",
      text,
      meta: {
        model: json.model ?? model,
        tokensIn: json.usage?.prompt_tokens,
        tokensOut: json.usage?.completion_tokens,
        latencyMs: Date.now() - started,
        route,
      },
    };
  } catch (err) {
    const msg = (err as Error).message;
    return {
      mode: "retrieval-only",
      text: retrievalOnly(question, memories) + `\n\n(model call failed, showing retrieval only: ${msg})`,
    };
  }
}

function retrievalOnly(question: string, memories: { relevance: number; content: string }[]): string {
  if (memories.length === 0) {
    return `Nothing in memory answers "${question}" yet. Teach me: notebook remember "<fact>"`;
  }
  const lines = [`Based on what I remember about "${question}":`];
  for (const m of memories) lines.push(`- ${m.content} (relevance ${m.relevance.toFixed(2)})`);
  return lines.join("\n");
}
