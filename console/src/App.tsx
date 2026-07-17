import { FormEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from '@tanstack/react-table'
import * as Dialog from '@radix-ui/react-dialog'
import * as Tabs from '@radix-ui/react-tabs'
import * as Tooltip from '@radix-ui/react-tooltip'
import {
  Activity, ArrowLeft, BookOpen, Check, ChevronRight, CircleAlert, Clock3,
  FileSearch, Filter, FolderSearch, Keyboard, Link2, ListFilter,
  LockKeyhole, MessageSquareText, Search, ShieldCheck, UserRound,
  X,
} from 'lucide-react'
import { api, ApiError, BoundedAction, CaseActivity, CaseDetail, CaseDisposition,
  CaseEvidence, CaseState, CaseSummary, OperatorSession } from './api'

const stateLabels: Record<CaseState, string> = {
  Open: 'Open', InReview: 'In review', Resolved: 'Resolved', Dismissed: 'Dismissed',
}

export function App() {
  const session = useQuery({ queryKey: ['session'], queryFn: api.session, retry: false })
  if (session.isPending) return <PageStatus kind="loading" title="Opening the forensic workbench" />
  if (session.error instanceof ApiError && session.error.status === 401) return <SignIn />
  if (session.isError) return <PageStatus kind="error" title="The console session could not be loaded"
    detail={session.error.message} action="Try again" onAction={() => void session.refetch()} />
  if (!session.data.tenantId || !session.data.environmentId) return <PageStatus kind="error"
    title="Your operator identity is missing its workspace binding"
    detail="Ask an administrator to add tenant_id and environment_id claims to your console access." />
  return <Console session={session.data} />
}

function SignIn() {
  return <main className="sign-in-shell">
    <div className="sign-in-mark" aria-hidden="true">C</div>
    <p className="eyebrow">Certael operator console</p>
    <h1>Evidence before conclusion.</h1>
    <p>Sign in with your authorized game-security identity to investigate evidence and operate bounded cases.</p>
    <a className="button primary" href="/bff/login?returnUrl=%2F">Sign in to the console</a>
  </main>
}

function Console({ session }: { session: OperatorSession }) {
  const [state, setState] = useState('')
  const [searchText, setSearchText] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [mobileDetail, setMobileDetail] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const workspaceRef = useRef<HTMLElement>(null)
  const returnFocusRef = useRef<HTMLElement | null>(null)
  const cases = useQuery({
    queryKey: ['cases', session.tenantId, session.environmentId, state, search],
    queryFn: () => api.cases(session, { state, search }),
  })
  useEffect(() => {
    if (cases.data?.length && !cases.data.some(value => value.caseId === selected))
      setSelected(cases.data[0]!.caseId)
    if (cases.data?.length === 0) setSelected(null)
  }, [cases.data, selected])
  const detail = useQuery({
    queryKey: ['case', selected],
    queryFn: () => api.case(session, selected!),
    enabled: selected !== null,
  })
  useEffect(() => {
    const shortcuts = (event: globalThis.KeyboardEvent) => {
      if (event.key === '/' && !(event.target instanceof HTMLInputElement)
        && !(event.target instanceof HTMLTextAreaElement)) {
        event.preventDefault(); searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', shortcuts)
    return () => window.removeEventListener('keydown', shortcuts)
  }, [])
  const selectCase = (id: string) => {
    setSelected(id)
    if (window.matchMedia('(max-width: 59.99rem)').matches) {
      returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
      setMobileDetail(true)
      requestAnimationFrame(() => workspaceRef.current?.focus())
    }
  }
  const closeMobileDetail = () => {
    setMobileDetail(false)
    requestAnimationFrame(() => returnFocusRef.current?.focus())
  }

  return <div className="console-shell">
    <a className="skip-link" href="#investigation-queue">Skip to investigation queue</a>
    <a className="skip-link skip-workspace" href="#case-workspace">Skip to case workspace</a>
    <NavRail session={session} />
    <aside id="investigation-queue" tabIndex={-1}
      className={`queue-pane ${mobileDetail ? 'mobile-hidden' : ''}`} aria-label="Investigation queue">
      <header className="queue-header">
        <div><p className="section-label">Investigation queue</p><h1>Cases</h1></div>
      </header>
      <Tabs.Root value={state} onValueChange={setState} className="queue-tabs">
        <Tabs.List aria-label="Filter cases by state">
          <Tabs.Trigger value="">Active</Tabs.Trigger>
          <Tabs.Trigger value="Open">Open</Tabs.Trigger>
          <Tabs.Trigger value="InReview">In review</Tabs.Trigger>
        </Tabs.List>
      </Tabs.Root>
      <form className="queue-search" onSubmit={(event) => {
        event.preventDefault(); setSearch(searchText.trim())
      }}>
        <label htmlFor="case-search">Search cases</label>
        <div className="input-with-icon"><Search aria-hidden="true" />
          <input ref={searchRef} id="case-search" value={searchText}
            onChange={event => setSearchText(event.target.value)} placeholder="Case, player, or finding" />
          <button type="submit" className="search-submit" aria-label="Apply case search"><ChevronRight /></button>
        </div>
      </form>
      <div className="filter-summary"><ListFilter aria-hidden="true" />
        <span>{state ? stateLabels[state as CaseState] : 'Open and in-review cases'}</span>
        {search && <button onClick={() => { setSearch(''); setSearchText('') }}>Clear search</button>}
      </div>
      <CaseQueue cases={cases.data} pending={cases.isPending} error={cases.error}
        selected={selected} onSelect={selectCase} onRetry={() => void cases.refetch()} />
    </aside>
    <main ref={workspaceRef} id="case-workspace" tabIndex={-1} className={`workspace ${mobileDetail ? 'mobile-visible' : ''}`}>
      <button className="mobile-back" onClick={closeMobileDetail}>
        <ArrowLeft aria-hidden="true" /> Back to case queue
      </button>
      {!selected ? <WorkspaceEmpty filtered={Boolean(state || search)} />
        : detail.isPending ? <CaseSkeleton />
        : detail.isError ? <PageStatus kind="error" title="This case could not be loaded"
          detail={detail.error.message} action="Try again" onAction={() => void detail.refetch()} compact />
        : <CaseWorkspace detail={detail.data} session={session} />}
    </main>
    <ShortcutFooter />
  </div>
}

function NavRail({ session }: { session: OperatorSession }) {
  return <nav className="nav-rail" aria-label="Primary navigation">
    <div className="product-mark" aria-label="Certael">C</div>
    <div className="nav-items"><Tooltip.Root><Tooltip.Trigger asChild>
      <button className="current" aria-current="page" aria-label="Investigations"><FolderSearch /></button>
    </Tooltip.Trigger><Tooltip.Portal><Tooltip.Content side="right" className="tooltip">
      Investigations<Tooltip.Arrow className="tooltip-arrow" /></Tooltip.Content></Tooltip.Portal></Tooltip.Root></div>
    <div className="nav-spacer" />
    <div className="operator-avatar" title={session.name ?? session.subject}
      aria-label={`Signed in as ${session.name ?? session.subject}`}>
      {(session.name ?? session.subject).slice(0, 2).toUpperCase()}
    </div>
  </nav>
}

function CaseQueue({ cases, pending, error, selected, onSelect, onRetry }: {
  cases?: CaseSummary[]; pending: boolean; error: Error | null; selected: string | null
  onSelect: (id: string) => void; onRetry: () => void
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([])
  if (pending) return <div className="queue-loading" role="status" aria-live="polite">
    <span className="sr-only">Loading cases</span>
    {Array.from({ length: 7 }, (_, index) => <div className="queue-skeleton" key={index} />)}
  </div>
  if (error) return <PageStatus compact kind="error" title="The case queue is unavailable"
    detail={error.message} action="Try again" onAction={onRetry} />
  if (!cases?.length) return <div className="empty-queue"><FolderSearch />
    <h2>No cases match this view</h2><p>Change the state filter or clear the search to broaden the queue.</p></div>
  const keyDown = (event: KeyboardEvent, index: number) => {
    const next = event.key === 'ArrowDown' ? Math.min(index + 1, cases.length - 1)
      : event.key === 'ArrowUp' ? Math.max(index - 1, 0) : null
    if (next !== null) { event.preventDefault(); refs.current[next]?.focus() }
  }
  return <ul className="case-list" aria-label={`${cases.length} cases`}>
    {cases.map((item, index) => <li key={item.caseId}><button
        ref={element => { refs.current[index] = element }}
        className={`case-row ${selected === item.caseId ? 'selected' : ''}`}
        aria-current={selected === item.caseId ? 'true' : undefined}
        onClick={() => onSelect(item.caseId)} onKeyDown={event => keyDown(event, index)}>
        <span className="case-row-top"><span className="machine">{shortId(item.caseId)}</span>
          <time dateTime={item.updatedAt}>{relativeTime(item.updatedAt)}</time></span>
        <strong title={item.title}>{item.title}</strong>
        <span className="case-player" title={item.playerSubject}><UserRound aria-hidden="true" />
          <span>{item.playerSubject}</span></span>
        <span className="case-row-bottom"><StateBadge state={item.state} />
          <span className="case-assignee" title={item.assignedTo ?? 'Unassigned'}>{item.assignedTo ?? 'Unassigned'}</span></span>
      </button></li>)}
  </ul>
}

function CaseWorkspace({ detail, session }: { detail: CaseDetail; session: OperatorSession }) {
  const [tab, setTab] = useState('dossier')
  const value = detail.case
  return <div className="case-workspace">
    <header className="case-header">
      <div className="case-title"><span className="machine">CASE-{shortId(value.caseId)}</span>
        <h1>{value.title}</h1></div>
      <dl className="case-header-meta">
        <div><dt>Status</dt><dd><StateBadge state={value.state} /></dd></div>
        <div><dt>Assignee</dt><dd>{value.assignedTo ?? 'Unassigned'}</dd></div>
        <div><dt>Disposition</dt><dd>{value.resolvedAt ? 'Recorded in audit' : 'Not set'}</dd></div>
      </dl>
      <div className="case-header-actions">
        <AssignmentAction detail={detail} session={session} />
        <WorkflowActions detail={detail} session={session} />
      </div>
    </header>
    <Tabs.Root value={tab} onValueChange={setTab} className="case-tabs">
      <Tabs.List aria-label="Case sections">
        <Tabs.Trigger value="dossier">Dossier</Tabs.Trigger>
        <Tabs.Trigger value="evidence">Evidence <span>{detail.evidence.length}</span></Tabs.Trigger>
        <Tabs.Trigger value="timeline">Timeline</Tabs.Trigger>
        <Tabs.Trigger value="notes">Notes <span>{detail.notes.length}</span></Tabs.Trigger>
        <Tabs.Trigger value="relationships">Relationships</Tabs.Trigger>
        <Tabs.Trigger value="audit">Audit</Tabs.Trigger>
      </Tabs.List>
      <div className="case-grid">
        <section className="case-primary">
          <Tabs.Content value="dossier"><Dossier detail={detail} session={session} /></Tabs.Content>
          <Tabs.Content value="evidence"><EvidenceView evidence={detail.evidence} /></Tabs.Content>
          <Tabs.Content value="timeline"><CombinedTimeline detail={detail} /></Tabs.Content>
          <Tabs.Content value="notes"><NotesView detail={detail} session={session} /></Tabs.Content>
          <Tabs.Content value="relationships"><RelationshipView evidence={detail.evidence} /></Tabs.Content>
          <Tabs.Content value="audit"><AuditView activity={detail.activity} /></Tabs.Content>
        </section>
        <aside className="activity-pane" aria-label="Case activity and bounded actions">
          <ActivityList activity={detail.activity} />
          <BoundedActionPanel detail={detail} session={session} />
        </aside>
      </div>
    </Tabs.Root>
  </div>
}

function Dossier({ detail, session }: { detail: CaseDetail; session: OperatorSession }) {
  const finding = detail.evidence.find(value => value.findingId) ?? detail.evidence[0]
  return <>
    <section className="finding-summary" aria-labelledby="finding-heading">
      <div className="finding-main"><p className="section-label">Derived finding</p>
        <h2 id="finding-heading">{detail.case.title}</h2><p>{detail.case.summary}</p></div>
      <dl className="facts-grid">
        <div><dt>Player</dt><dd className="machine">{detail.case.playerSubject}</dd></div>
        <div><dt>Game</dt><dd>{detail.case.gameId}</dd></div>
        <div><dt>Environment</dt><dd>{detail.case.environmentId}</dd></div>
        <div><dt>Signed policy</dt><dd className="machine">{detail.case.signedPolicyId} · {detail.case.signedPolicyVersion}</dd></div>
        <div><dt>Case opened</dt><dd>{formatTime(detail.case.createdAt)}</dd></div>
        <div><dt>Replay digest</dt><dd className="machine">{finding ? shortDigest(finding.replayDigest) : 'Not available'}</dd></div>
      </dl>
      <div className="explanation"><p className="section-label">Finding explanation</p>
        <p>{finding?.ruleId ? <>Rule <span className="machine">{finding.ruleId} · {finding.ruleVersion}</span> produced this finding from {detail.evidence.filter(value => value.findingId).length} normalized evidence records.</> : 'The verdict is attached; no normalized finding record remains.'}</p>
        <p className="integrity-line"><ShieldCheck aria-hidden="true" /> Exact policy, fields, timestamps, and replay digest are retained.</p>
      </div>
    </section>
    <section className="section-block"><div className="section-heading"><div>
      <p className="section-label">Evidence</p><h2>Authoritative chain</h2></div>
      <span>{detail.evidence.length} records</span></div>
      <EvidenceTable evidence={detail.evidence.slice(0, 8)} />
    </section>
    <NotesView detail={detail} session={session} compact />
    <div className="mobile-bounded"><BoundedActionPanel detail={detail} session={session} /></div>
  </>
}

const evidenceColumn = createColumnHelper<CaseEvidence>()
function EvidenceTable({ evidence }: { evidence: CaseEvidence[] }) {
  const columns = useMemo(() => [
    evidenceColumn.accessor('findingId', { header: 'Evidence', cell: info =>
      <span className="evidence-id"><FileSearch /> <span className="machine">{info.getValue() ? shortId(info.getValue()!) : shortId(info.row.original.verdictId)}</span></span> }),
    evidenceColumn.accessor('signalFamily', { header: 'Signal', cell: info => info.getValue() ?? 'Verdict' }),
    evidenceColumn.accessor('observedAt', { header: 'Observed UTC', cell: info => <time className="machine" dateTime={info.getValue()}>{formatTime(info.getValue())}</time> }),
    evidenceColumn.accessor('ruleId', { header: 'Rule', cell: info => <span className="machine">{info.getValue() ? `${info.getValue()} · ${info.row.original.ruleVersion}` : 'Verdict aggregate'}</span> }),
    evidenceColumn.accessor('trust', { header: 'Integrity', cell: info => <span className="integrity"><Check />{info.getValue() ?? 'Bundled'}</span> }),
  ], [])
  const table = useReactTable({ data: evidence, columns, getCoreRowModel: getCoreRowModel() })
  if (!evidence.length) return <InlineEmpty title="Evidence was deleted under retention or privacy policy"
    detail="The retained case history remains pseudonymized and auditable." />
  return <div className="table-scroll" tabIndex={0} aria-label="Scrollable evidence table">
    <table><thead>{table.getHeaderGroups().map(group => <tr key={group.id}>
      {group.headers.map(header => <th key={header.id} scope="col">{flexRender(header.column.columnDef.header, header.getContext())}</th>)}
    </tr>)}</thead><tbody>{table.getRowModel().rows.map(row => <tr key={row.id}>
      {row.getVisibleCells().map(cell => <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}</tr>)}</tbody></table>
  </div>
}

function EvidenceView({ evidence }: { evidence: CaseEvidence[] }) {
  return <section className="section-block full-height"><div className="section-heading"><div>
    <p className="section-label">Evidence search</p><h2>Case evidence</h2></div>
    <span>{evidence.length} records</span></div><EvidenceTable evidence={evidence} /></section>
}

function CombinedTimeline({ detail }: { detail: CaseDetail }) {
  const entries = [
    ...detail.evidence.map(item => ({ id: item.findingId ?? item.verdictId, at: item.observedAt,
      title: item.signalFamily ?? 'Verdict created', detail: item.ruleId ? `${item.ruleId} · ${item.ruleVersion}` : 'Immutable evidence bundle' })),
    ...detail.activity.map(item => ({ id: item.activityId, at: item.occurredAt,
      title: activityLabel(item.activityType), detail: item.reason })),
  ].sort((a, b) => a.at.localeCompare(b.at))
  return <section className="section-block"><div className="section-heading"><div>
    <p className="section-label">Player and case timeline</p><h2>Reconstruct the sequence</h2></div></div>
    <ol className="timeline">{entries.map(entry => <li key={`${entry.id}-${entry.at}`}>
      <span className="timeline-node" aria-hidden="true" /><time dateTime={entry.at}>{formatTime(entry.at)}</time>
      <div><strong>{entry.title}</strong><p>{entry.detail}</p></div></li>)}</ol></section>
}

function NotesView({ detail, session, compact = false }: { detail: CaseDetail; session: OperatorSession; compact?: boolean }) {
  const client = useQueryClient(); const [body, setBody] = useState('')
  const mutation = useMutation({ mutationFn: () => api.mutate(detail.case.caseId, 'notes', {
    tenantId: session.tenantId, environmentId: session.environmentId, body,
    expectedVersion: detail.case.version,
  }), onSuccess: async () => { setBody(''); await client.invalidateQueries({ queryKey: ['case', detail.case.caseId] }) } })
  const canWrite = session.scopes.includes('cases:write')
  return <section className={`section-block notes-section ${compact ? 'compact' : ''}`}>
    <div className="section-heading"><div><p className="section-label">Operator notes</p>
      <h2>{compact ? 'Investigation notes' : 'Internal case notes'}</h2></div><span>{detail.notes.length}</span></div>
    {detail.notes.length ? <ol className="notes-list">{detail.notes.map(note => <li key={note.noteId}>
      <div><strong>{note.authorSubject}</strong><time dateTime={note.createdAt}>{formatTime(note.createdAt)}</time></div><p>{note.body}</p>
    </li>)}</ol> : <InlineEmpty title="No operator notes yet" detail="Add the first note to record investigative judgment separately from derived evidence." />}
    {canWrite ? <form className="note-form" onSubmit={event => { event.preventDefault(); mutation.mutate() }}>
      <label htmlFor={`note-${detail.case.caseId}`}>Add internal note</label>
      <textarea id={`note-${detail.case.caseId}`} value={body} maxLength={4096} required
        onChange={event => setBody(event.target.value)} placeholder="Record what you observed and why it matters." />
      <div className="form-footer"><span>{body.length} / 4096</span>
        <button className="button secondary" disabled={!body.trim() || mutation.isPending}>
          {mutation.isPending ? 'Adding note…' : 'Add note'}</button></div>
      {mutation.isError && <FormError error={mutation.error} />}
      {mutation.isSuccess && <span className="sr-only" role="status">Note added to the case.</span>}
    </form> : <PermissionMessage scope="cases:write" />}
  </section>
}

function RelationshipView({ evidence }: { evidence: CaseEvidence[] }) {
  const linked = evidence.filter(value => value.findingId)
  return <section className="section-block"><div className="section-heading"><div>
    <p className="section-label">Relationship analysis</p><h2>Explainable evidence links</h2></div></div>
    {linked.length ? <ol className="relationship-list">{linked.map((item, index) => <li key={item.findingId}>
      <span className="relationship-index">{String(index + 1).padStart(2, '0')}</span>
      <div><strong>{item.signalFamily}</strong><p><span className="machine">{item.ruleId} · {item.ruleVersion}</span></p></div>
      <Link2 aria-label="Linked through the attached verdict" /></li>)}</ol>
      : <InlineEmpty title="No relationship projection is attached"
        detail="Relationship views appear only when a signed analytical rule records exact supporting edges." />}
  </section>
}

function AuditView({ activity }: { activity: CaseActivity[] }) {
  return <section className="section-block"><div className="section-heading"><div>
    <p className="section-label">Immutable audit history</p><h2>Case activity</h2></div></div>
    <ActivityList activity={activity} expanded /></section>
}

function ActivityList({ activity, expanded = false }: { activity: CaseActivity[]; expanded?: boolean }) {
  return <section className={expanded ? 'activity-expanded' : 'activity-list'}>
    {!expanded && <div className="aside-heading"><h2>Case activity</h2><span>{activity.length}</span></div>}
    {activity.length ? <ol>{activity.map(item => <li key={item.activityId}>
      <span className="activity-icon" aria-hidden="true">{activityIcon(item.activityType)}</span>
      <div><strong>{activityLabel(item.activityType)}</strong><p>{item.reason}</p>
        <span>{item.actorSubject} · <time dateTime={item.occurredAt}>{formatTime(item.occurredAt)}</time></span></div>
    </li>)}</ol> : <InlineEmpty title="No activity remains" detail="New case operations will appear here as immutable records." />}
  </section>
}

function AssignmentAction({ detail, session }: { detail: CaseDetail; session: OperatorSession }) {
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const client = useQueryClient()
  const assignedToMe = detail.case.assignedTo === session.subject
  const mutation = useMutation({
    mutationFn: () => api.mutate<CaseSummary>(detail.case.caseId, 'assignment', {
      tenantId: session.tenantId,
      environmentId: session.environmentId,
      assignedTo: assignedToMe ? null : session.subject,
      reason,
      expectedVersion: detail.case.version,
    }),
    onSuccess: async () => {
      setOpen(false)
      setReason('')
      await client.invalidateQueries({ queryKey: ['case', detail.case.caseId] })
      await client.invalidateQueries({ queryKey: ['cases'] })
    },
  })
  if (!session.scopes.includes('cases:write')) return null
  const label = assignedToMe ? 'Unassign' : detail.case.assignedTo ? 'Take ownership' : 'Assign to me'
  return <><Dialog.Root open={open} onOpenChange={setOpen}>
    <Dialog.Trigger asChild><button className="button ghost">{label}</button></Dialog.Trigger>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content">
      <div className="dialog-title-row"><Dialog.Title>{label}</Dialog.Title>
        <Dialog.Close className="icon-button" aria-label="Close"><X /></Dialog.Close></div>
      <Dialog.Description>{assignedToMe
        ? 'Return this case to the unassigned queue with an auditable reason.'
        : 'Record yourself as the accountable operator for this investigation.'}</Dialog.Description>
      <label>Reason<textarea value={reason} onChange={event => setReason(event.target.value)}
        required maxLength={2048} /></label>
      {mutation.isError && <FormError error={mutation.error} />}
      <div className="dialog-actions"><Dialog.Close asChild><button className="button ghost">Cancel</button></Dialog.Close>
        <button className="button primary" disabled={!reason.trim() || mutation.isPending}
          onClick={() => mutation.mutate()}>{mutation.isPending ? 'Recording…' : label}</button></div>
    </Dialog.Content></Dialog.Portal>
  </Dialog.Root>{mutation.isSuccess && <span className="sr-only" role="status">
    Case assignment recorded.</span>}</>
}

function WorkflowActions({ detail, session }: { detail: CaseDetail; session: OperatorSession }) {
  const [open, setOpen] = useState(false); const [reason, setReason] = useState('')
  const [disposition, setDisposition] = useState<CaseDisposition>('ConfirmedAbuse')
  const client = useQueryClient(); const current = detail.case.state
  const target: CaseState = current === 'Open' ? 'InReview' : current === 'InReview' ? 'Resolved' : 'Open'
  const label = current === 'Open' ? 'Begin review' : current === 'InReview' ? 'Resolve case' : 'Reopen case'
  const mutation = useMutation({ mutationFn: () => api.mutate(detail.case.caseId, 'transition', {
    tenantId: session.tenantId, environmentId: session.environmentId, targetState: target,
    disposition: current === 'InReview' ? disposition : null, reason, expectedVersion: detail.case.version,
  }), onSuccess: async () => { setOpen(false); setReason(''); await client.invalidateQueries({ queryKey: ['case', detail.case.caseId] }); await client.invalidateQueries({ queryKey: ['cases'] }) } })
  if (!session.scopes.includes('cases:write')) return null
  return <><Dialog.Root open={open} onOpenChange={setOpen}><Dialog.Trigger asChild>
    <button className="button secondary">{label}</button></Dialog.Trigger><Dialog.Portal>
    <Dialog.Overlay className="dialog-overlay" /><Dialog.Content className="dialog-content">
      <div className="dialog-title-row"><Dialog.Title>{label}</Dialog.Title><Dialog.Close className="icon-button" aria-label="Close"><X /></Dialog.Close></div>
      <Dialog.Description>{target === 'InReview' ? 'Mark this case as actively owned and under review.' : target === 'Open' ? 'Return this case to the active queue with an explicit reason.' : 'Record the final disposition and why the evidence supports it.'}</Dialog.Description>
      {current === 'InReview' && <label>Disposition<select value={disposition}
        onChange={event => setDisposition(event.target.value as CaseDisposition)}>
        <option value="ConfirmedAbuse">Confirmed abuse</option><option value="FalsePositive">False positive</option>
        <option value="ExpectedBehavior">Expected behavior</option><option value="InsufficientEvidence">Insufficient evidence</option>
        <option value="Duplicate">Duplicate</option></select></label>}
      <label>Reason<textarea value={reason} onChange={event => setReason(event.target.value)} required maxLength={2048} /></label>
      {mutation.isError && <FormError error={mutation.error} />}
      <div className="dialog-actions"><Dialog.Close asChild><button className="button ghost">Keep reviewing</button></Dialog.Close>
        <button className="button primary" disabled={!reason.trim() || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Recording…' : label}</button></div>
    </Dialog.Content></Dialog.Portal></Dialog.Root>{mutation.isSuccess &&
      <span className="sr-only" role="status">Case state updated.</span>}</>
}

const boundedConsequences: Record<string, string> = {
  RevokeSession: 'Ends the current protected session; does not ban the player.',
  RejectAction: 'Rejects the specified pending authoritative action only.',
  IncreaseSampling: 'Temporarily increases signed evidence sampling for the target session.',
  TemporaryRestriction: 'Applies the game-defined temporary restriction; never creates a permanent ban.',
  RecommendKick: 'Sends a bounded kick recommendation to the integrating game.',
}

function BoundedActionPanel({ detail, session }: { detail: CaseDetail; session: OperatorSession }) {
  const [kind, setKind] = useState('RevokeSession'); const [targetId, setTargetId] = useState('')
  const [reason, setReason] = useState(''); const [confirming, setConfirming] = useState(false)
  const client = useQueryClient(); const permitted = session.scopes.includes('cases:act')
  const mutation = useMutation({ mutationFn: () => api.mutate<BoundedAction>(detail.case.caseId, 'actions', {
    tenantId: session.tenantId, environmentId: session.environmentId, kind,
    targetType: kind === 'RejectAction' ? 'action' : 'session', targetId, reason,
    expectedVersion: detail.case.version,
  }), onSuccess: async () => { setConfirming(false); setReason(''); await client.invalidateQueries({ queryKey: ['case', detail.case.caseId] }) } })
  return <section className="bounded-action"><div className="aside-heading"><h2>Bounded action</h2><LockKeyhole /></div>
    {mutation.isSuccess && <span className="sr-only" role="status">Bounded action approved and recorded.</span>}
    {detail.case.state !== 'InReview' ? <p className="aside-message">Move the case into review before approving a restrictive action.</p>
      : !permitted ? <PermissionMessage scope="cases:act" /> : <form onSubmit={(event) => { event.preventDefault(); setConfirming(true) }}>
        <label>Action<select value={kind} onChange={event => setKind(event.target.value)}>
          <option value="RevokeSession">Revoke active session</option><option value="RejectAction">Reject pending action</option>
          <option value="IncreaseSampling">Increase sampling</option><option value="TemporaryRestriction">Temporary restriction</option>
          <option value="RecommendKick">Recommend kick</option></select></label>
        <p className="consequence"><CircleAlert /> <span><strong>Consequence</strong>{boundedConsequences[kind]}</span></p>
        <label>Target identifier<input className="machine" value={targetId} onChange={event => setTargetId(event.target.value)} required maxLength={128} /></label>
        <label>Required reason<textarea value={reason} onChange={event => setReason(event.target.value)} required maxLength={2048} placeholder="Explain why this bounded action is necessary." /></label>
        <p className="authorization"><ShieldCheck /> Authorized by delegated <span className="machine">cases:act</span> scope</p>
        <button className="button primary full" disabled={!targetId.trim() || !reason.trim()}>Review action</button>
      </form>}
    <Dialog.Root open={confirming} onOpenChange={setConfirming}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <Dialog.Content className="dialog-content"><div className="dialog-title-row"><Dialog.Title>Approve {humanize(kind)}</Dialog.Title>
        <Dialog.Close className="icon-button" aria-label="Close"><X /></Dialog.Close></div>
        <Dialog.Description>{boundedConsequences[kind]} This approval and its reason become immutable case activity.</Dialog.Description>
        <dl className="confirmation-details"><div><dt>Target</dt><dd className="machine">{targetId}</dd></div><div><dt>Reason</dt><dd>{reason}</dd></div></dl>
        {mutation.isError && <FormError error={mutation.error} />}
        <div className="dialog-actions"><Dialog.Close asChild><button className="button ghost">Keep reviewing</button></Dialog.Close>
          <button className="button restrictive" disabled={mutation.isPending} onClick={() => mutation.mutate()}>
            {mutation.isPending ? 'Approving…' : `Approve ${humanize(kind)}`}</button></div>
      </Dialog.Content></Dialog.Portal></Dialog.Root>
  </section>
}

function StateBadge({ state }: { state: CaseState }) {
  return <span className={`state-badge state-${state.toLowerCase()}`}><span aria-hidden="true" />{stateLabels[state]}</span>
}

function ShortcutFooter() {
  const [open, setOpen] = useState(false)
  useEffect(() => { const key = (event: globalThis.KeyboardEvent) => { if (event.key === '?') setOpen(true) }
    window.addEventListener('keydown', key); return () => window.removeEventListener('keydown', key) }, [])
  return <footer className="shortcut-footer"><span>Navigate <kbd>↑</kbd><kbd>↓</kbd></span><span>Open <kbd>Enter</kbd></span>
    <span>Search <kbd>/</kbd></span><button onClick={() => setOpen(true)}>Shortcuts <kbd>?</kbd></button>
    <Dialog.Root open={open} onOpenChange={setOpen}><Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
      <Dialog.Content className="dialog-content shortcuts"><div className="dialog-title-row"><Dialog.Title>Keyboard shortcuts</Dialog.Title>
        <Dialog.Close className="icon-button" aria-label="Close"><X /></Dialog.Close></div>
        <dl><div><dt><kbd>/</kbd></dt><dd>Focus case search</dd></div><div><dt><kbd>↑</kbd><kbd>↓</kbd></dt><dd>Move through the case queue</dd></div>
          <div><dt><kbd>Tab</kbd></dt><dd>Move between controls and case sections</dd></div><div><dt><kbd>Esc</kbd></dt><dd>Close the active dialog</dd></div></dl>
      </Dialog.Content></Dialog.Portal></Dialog.Root></footer>
}

function PageStatus({ kind, title, detail, action, onAction, compact = false }: {
  kind: 'loading' | 'error'; title: string; detail?: string; action?: string; onAction?: () => void; compact?: boolean
}) {
  return <div className={`page-status ${compact ? 'compact' : ''}`} role={kind === 'error' ? 'alert' : 'status'}>
    {kind === 'loading' ? <div className="status-spinner" /> : <CircleAlert />}
    <h1>{title}</h1>{detail && <p>{detail}</p>}{action && <button className="button secondary" onClick={onAction}>{action}</button>}
  </div>
}

function WorkspaceEmpty({ filtered }: { filtered: boolean }) { return <div className="workspace-empty"><BookOpen />
  <h1>{filtered ? 'No case is selected' : 'The investigation queue is clear'}</h1>
  <p>{filtered ? 'Choose a case from the queue to inspect its evidence and audit history.' : 'New cases appear only when a signed policy reaches its review or bounded-action threshold.'}</p></div> }
function CaseSkeleton() { return <div className="case-skeleton" role="status" aria-live="polite">
  <span className="sr-only">Loading case</span><div /><div /><div /><div /></div> }
function InlineEmpty({ title, detail }: { title: string; detail: string }) { return <div className="inline-empty"><FileSearch /><div><h3>{title}</h3><p>{detail}</p></div></div> }
function PermissionMessage({ scope }: { scope: string }) { return <p className="permission-message"><LockKeyhole /> Your delegated identity does not include <span className="machine">{scope}</span>.</p> }
function FormError({ error }: { error: Error }) { return <p className="form-error" role="alert"><CircleAlert /> {error instanceof ApiError && error.status === 409 ? 'The case changed in another session. Refresh it before trying again.' : error.message}</p> }
function activityLabel(value: string) { return value.replace(/([a-z])([A-Z])/g, '$1 $2') }
function activityIcon(value: string) { if (value.includes('Note')) return <MessageSquareText />; if (value.includes('Action')) return <LockKeyhole />; if (value.includes('Evidence')) return <Link2 />; return <Clock3 /> }
function shortId(value: string) { return value.replaceAll('-', '').slice(-12).toUpperCase() }
function shortDigest(value: string) { const text = value.replaceAll('=', ''); return text.length > 18 ? `${text.slice(0, 9)}…${text.slice(-5)}` : text }
function formatTime(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(value)) + ' UTC' }
function relativeTime(value: string) { const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000)); return minutes < 1 ? 'now' : minutes < 60 ? `${minutes}m ago` : minutes < 1440 ? `${Math.floor(minutes / 60)}h ago` : `${Math.floor(minutes / 1440)}d ago` }
function humanize(value: string) { return value.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase() }
