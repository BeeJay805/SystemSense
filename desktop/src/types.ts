export interface Evidence {
  evidence_id?: string;
  probe_id?: string;
  summary?: string;
  status?: string;
  statement_kind?: string;
  source_id?: string;
  source_type?: string;
  observed_at?: string;
  captured_at?: string;
  historical?: boolean;
  limitations?: string[];
  facts?: Record<string, unknown>;
}
export interface Case {
  case_id?: string;
  objective?: string;
  status: string;
  outcome?: string;
  created_at?: string;
  updated_at?: string;
  summary?: string;
  stop_reason?: string;
  cancellation_requested?: boolean;
  evidence?: Evidence[];
  evidence_count?: number;
  evidence_view_truncated?: boolean;
  retrieval?: { truncated?: boolean };
  assessment?: {
    disposition?: string;
    explanation?: string;
    limitations?: string[];
    evidence_ids?: string[];
  };
  warnings?: string[];
  pending_probe_ids?: string[];
  coverage?: {
    probe_id: string;
    status: string;
    reason?: string;
    summary?: string;
  }[];
  measurement_gaps?: { reason: string }[];
  hypotheses?: {
    status?: string;
    statement?: string;
    summary?: string;
    supporting_evidence_ids?: string[];
    contradicting_evidence_ids?: string[];
  }[];
  timeline?: {
    event?: string;
    detail?: string;
    occurred_at?: string;
    created_at?: string;
  }[];
  process_target_inventory?: {
    unavailable_reason?: string;
    inventory_complete?: boolean;
    omitted_process_count?: number;
    candidates?: {
      candidate_id: string;
      name: string;
      pid: number;
      creation_time: string;
      evidence_id: string;
    }[];
  };
}
export interface Capabilities {
  read_only?: boolean;
  active_case_id?: string | null;
  inference?: {
    enabled?: boolean;
    configured_enabled?: boolean;
    mode?: string;
  };
  probes?: {
    probe_id: string;
    description?: string;
    permission_class?: string;
  }[];
}
export interface DesktopAPI {
  capabilities(): Promise<Capabilities>;
  listCases(): Promise<{ cases: Case[] }>;
  getCase(id: string): Promise<Case>;
  start(value: { objective: string }): Promise<Case>;
  cancel(id: string): Promise<Case>;
  resume(id: string): Promise<Case>;
  selectTarget(value: { caseId: string; candidateId: string }): Promise<Case>;
  exportCase(id: string): Promise<{ saved: boolean }>;
  quit(): Promise<void>;
}
declare global {
  interface Window {
    systemsense?: DesktopAPI;
  }
}
