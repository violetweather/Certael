export type CaseState = 'Open' | 'InReview' | 'Resolved' | 'Dismissed'
export type CaseDisposition =
  | 'ConfirmedAbuse'
  | 'FalsePositive'
  | 'ExpectedBehavior'
  | 'InsufficientEvidence'
  | 'Duplicate'

export interface OperatorSession {
  subject: string
  name: string | null
  tenantId: string
  environmentId: string
  scopes: string[]
}

export interface CaseSummary {
  caseId: string
  tenantId: string
  gameId: string
  environmentId: string
  playerSubject: string
  title: string
  summary: string
  state: CaseState
  signedPolicyId: string
  signedPolicyVersion: string
  assignedTo: string | null
  version: number
  createdAt: string
  updatedAt: string
  resolvedAt: string | null
  category: string
  metadata: CaseMetadataValue[] | null
  highestRisk: number
  highestConfidence: number
  ruleIds: string[] | null
  signalFamilies: string[] | null
}

export type CaseMetadataType = 'Text' | 'Number' | 'Boolean' | 'DateTime' | 'Enumeration' | 'Identifier'
export interface CaseMetadataValue {
  key: string
  type: CaseMetadataType
  value: string
  sensitive: boolean
  searchable: boolean
}

export interface CaseQueuePage {
  items: CaseSummary[]
  nextCursor: string | null
  hasMore: boolean
}

export interface CaseQueueFilters {
  state?: string
  search?: string
  category?: string
  ruleId?: string
  signalFamily?: string
  sortBy?: 'UpdatedAt' | 'CreatedAt' | 'Risk' | 'Confidence' | 'Rule' | 'Signal'
  sortDirection?: 'Ascending' | 'Descending'
  cursor?: string
  pageSize?: number
}

export interface CaseCategoryDefinition {
  key: string
  displayName: string
  description: string
  enabled: boolean
  sortOrder: number
  version: number
  updatedAt: string
}

export interface CaseMetadataDefinition {
  key: string
  label: string
  type: CaseMetadataType
  enumerationValues: string[]
  sensitive: boolean
  searchable: boolean
  required: boolean
  enabled: boolean
  version: number
  updatedAt: string
}

export interface CaseSettingsSnapshot {
  scope: { tenantId: string; gameId: string; environmentId: string }
  categories: CaseCategoryDefinition[]
  metadataDefinitions: CaseMetadataDefinition[]
}

export interface CaseEvidence {
  verdictId: string
  findingId: string | null
  ruleId: string
  ruleVersion: string
  signalFamily: string | null
  trust: string | null
  riskContribution: number | null
  confidence: number | null
  observedAt: string
  replayDigest: string
  fieldsJson: string
}

export interface CaseNote {
  noteId: string
  authorSubject: string
  body: string
  createdAt: string
}

export interface CaseActivity {
  activityId: string
  actorSubject: string
  activityType: string
  reason: string
  detailsJson: string
  occurredAt: string
}

export interface BoundedAction {
  boundedActionId: string
  kind: string
  targetType: string
  targetId: string
  reason: string
  requestedBy: string
  approvedBy: string
  status: string
  publicResult: string | null
  requestedAt: string
  completedAt: string | null
}

export interface CaseDetail {
  case: CaseSummary
  evidence: CaseEvidence[]
  notes: CaseNote[]
  activity: CaseActivity[]
  actions: BoundedAction[]
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: 'same-origin', ...init })
  if (!response.ok) {
    const problem = await response.json().catch(() => null) as { error?: string; title?: string } | null
    throw new ApiError(response.status, problem?.error ?? problem?.title ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as T
  return await response.json() as T
}

let antiforgeryToken: string | null = null
async function csrf(): Promise<string> {
  if (antiforgeryToken) return antiforgeryToken
  const value = await request<{ requestToken: string }>('/bff/antiforgery')
  antiforgeryToken = value.requestToken
  return antiforgeryToken
}

export const api = {
  session: () => request<OperatorSession>('/bff/session'),
  casePage: (session: OperatorSession, filters: CaseQueueFilters) => {
    const query = new URLSearchParams({
      tenantId: session.tenantId,
      environmentId: session.environmentId,
      pageSize: String(filters.pageSize ?? 25),
    })
    if (filters.state) query.set('state', filters.state)
    if (filters.search) query.set('search', filters.search)
    if (filters.category) query.set('category', filters.category)
    if (filters.ruleId) query.set('ruleId', filters.ruleId)
    if (filters.signalFamily) query.set('signalFamily', filters.signalFamily)
    if (filters.sortBy) query.set('sortBy', filters.sortBy)
    if (filters.sortDirection) query.set('sortDirection', filters.sortDirection)
    if (filters.cursor) query.set('cursor', filters.cursor)
    return request<CaseQueuePage>(`/bff/api/cases/page?${query}`)
  },
  case: (session: OperatorSession, caseId: string) => {
    const query = new URLSearchParams({ tenantId: session.tenantId, environmentId: session.environmentId })
    return request<CaseDetail>(`/bff/api/cases/${caseId}?${query}`)
  },
  mutate: async <T>(caseId: string, path: string, body: object) => request<T>(
    `/bff/api/cases/${caseId}/${path}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Certael-CSRF': await csrf() },
      body: JSON.stringify(body),
    },
  ),
  updateMetadata: async (caseId: string, body: object) => request<CaseSummary>(
    `/bff/api/cases/${caseId}/metadata`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Certael-CSRF': await csrf() },
      body: JSON.stringify(body),
    }),
  caseSettings: (session: OperatorSession, gameId: string) => {
    const query = new URLSearchParams({ tenantId: session.tenantId, gameId, environmentId: session.environmentId })
    return request<CaseSettingsSnapshot>(`/bff/api/case-settings?${query}`)
  },
  upsertCategory: async (key: string, body: object) => request<CaseCategoryDefinition>(
    `/bff/api/case-settings/categories/${encodeURIComponent(key)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Certael-CSRF': await csrf() },
      body: JSON.stringify(body),
    }),
  upsertMetadataDefinition: async (key: string, body: object) => request<CaseMetadataDefinition>(
    `/bff/api/case-settings/metadata/${encodeURIComponent(key)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Certael-CSRF': await csrf() },
      body: JSON.stringify(body),
    }),
}
