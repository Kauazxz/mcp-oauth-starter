import { randomUUID } from "node:crypto";

export interface Note {
  id: string;
  title: string;
  body: string;
  createdAt: string;
}

export interface NotesStore {
  create(userId: string, title: string, body: string): Promise<Note>;
  list(userId: string): Promise<Note[]>;
  search(userId: string, query: string): Promise<Note[]>;
}

/** Demo data behind the MCP tools. Every method is scoped to one user id. */
export class MemoryNotesStore implements NotesStore {
  private notes = new Map<string, Note[]>();

  async create(userId: string, title: string, body: string) {
    const note: Note = { id: randomUUID(), title, body, createdAt: new Date().toISOString() };
    this.notes.set(userId, [...(this.notes.get(userId) ?? []), note]);
    return note;
  }

  async list(userId: string) {
    return [...(this.notes.get(userId) ?? [])];
  }

  async search(userId: string, query: string) {
    const q = query.toLowerCase();
    return (await this.list(userId)).filter((n) => `${n.title}\n${n.body}`.toLowerCase().includes(q));
  }
}
