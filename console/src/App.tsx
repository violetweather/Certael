import { FormEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from '@tanstack/react-table'
import * as Dialog from '@radix-ui/react-dialog'
import * as Tabs from '@radix-ui/react-tabs'
import * as Tooltip from '@radix-ui/react-tooltip'
import {
  Activity, ArrowLeft, BookOpen, Check, ChevronLeft, ChevronRight, CircleAlert, Clock3,
  FileSearch, Filter, FolderSearch, Keyboard, Link2, ListFilter,
  LockKeyhole, MessageSquareText, Search, Settings, ShieldCheck, SlidersHorizontal, UserRound,
  X,
} from 'lucide-react'
import { api, ApiError, BoundedAction, CaseActivity, CaseDetail, CaseDisposition,
  CaseEvidence, CaseMetadataDefinition, CaseMetadataValue, CaseSettingsSnapshot,
  CaseState, CaseSummary, OperatorSession } from './api'

const stateLabels: Record<CaseState, string> = {
  Open: 'Open', InReview: 'In review', Resolved: 'Resolved', Dismissed: 'Dismissed',
}
const signalFamilies = ['AuthoritativeContradiction', 'ProtocolViolation', 'BuildIntegrity',
  'RuntimeIntegrity', 'PlatformAttestation', 'BehavioralAnomaly', 'EconomyAnomaly', 'DeveloperReport']

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
  const [view, setView] = useState<'investigations' | 'settings'>('investigations')
  const [state, setState] = useState('')
  const [searchText, setSearchText] = useState('')
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [signalFamily, setSignalFamily] = useState('')
  const [sortBy, setSortBy] = useState<'UpdatedAt' | 'CreatedAt' | 'Risk' | 'Confidence' | 'Rule' | 'Signal'>('UpdatedAt')
  const [sortDirection, setSortDirection] = useState<'Ascending' | 'Descending'>('Descending')
  const [cursors, setCursors] = useState<string[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [mobileDetail, setMobileDetail] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const workspaceRef = useRef<HTMLElement>(null)
  const returnFocusRef = useRef<HTMLElement | null>(null)
  const cases = useQuery({
    queryKey: ['cases', session.tenantId, session.environmentId, state, search,
      category, ruleId, signalFamily, sortBy, sortDirection, cursors.at(-1) ?? ''],
    queryFn: () => api.casePage(session, { state, search, category, ruleId,
      signalFamily, sortBy, sortDirection, cursor: cursors.at(-1), pageSize: 25 }),
  })
  useEffect(() => {
    if (cases.data?.items.length && !cases.data.items.some(value => value.caseId === selected))
      setSelected(cases.data.items[0]!.caseId)
    if (cases.data?.items.length === 0) setSelected(null)
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
  const resetPage = () => setCursors([])
  const applyRuleFilter = (value: string) => {
    setRuleId(value); setSortBy('Rule'); setSortDirection('Ascending'); resetPage()
    setView('investigations'); setMobileDetail(false)
    requestAnimationFrame(() => searchRef.current?.focus())
  }
  const clearFilters = () => {
    setSearch(''); setSearchText(''); setCategory(''); setRuleId(''); setSignalFamily('')
    setSortBy('UpdatedAt'); setSortDirection('Descending'); resetPage()
  }
  const filterCount = [search, category, ruleId, signalFamily].filter(Boolean).length
  const activeGameId = cases.data?.items.find(item => item.caseId === selected)?.gameId
    ?? cases.data?.items[0]?.gameId ?? ''

  return <div className="console-shell">
    <a className="skip-link" href="#investigation-queue">Skip to investigation queue</a>
    <a className="skip-link skip-workspace" href="#case-workspace">Skip to case workspace</a>
    <NavRail session={session} view={view} onView={next => {
      setView(next); setMobileDetail(false)
    }} />
    {view === 'settings' ? <SettingsWorkspace session={session} initialGameId={activeGameId} /> : <>
    <aside id="investigation-queue" tabIndex={-1}
      className={`queue-pane ${mobileDetail ? 'mobile-hidden' : ''}`} aria-label="Investigation queue">
      <header className="queue-header">
        <div><p className="section-label">Investigation queue</p><h1>Cases</h1></div>
      </header>
      <Tabs.Root value={state} onValueChange={value => { setState(value); resetPage() }} className="queue-tabs">
        <Tabs.List aria-label="Filter cases by state">
          <Tabs.Trigger value="">Active</Tabs.Trigger>
          <Tabs.Trigger value="Open">Open</Tabs.Trigger>
          <Tabs.Trigger value="InReview">In review</Tabs.Trigger>
        </Tabs.List>
      </Tabs.Root>
      <form className="queue-search" onSubmit={(event) => {
        event.preventDefault(); setSearch(searchText.trim()); resetPage()
      }}>
        <label htmlFor="case-search">Search cases</label>
        <div className="input-with-icon"><Search aria-hidden="true" />
          <input ref={searchRef} id="case-search" value={searchText}
            onChange={event => setSearchText(event.target.value)} placeholder="Case, player, finding, or metadata" />
          <button type="submit" className="search-submit" aria-label="Apply case search"><ChevronRight /></button>
        </div>
      </form>
      <CaseFilterControls category={category} ruleId={ruleId} signalFamily={signalFamily}
        sortBy={sortBy} sortDirection={sortDirection} onCategory={value => { setCategory(value); resetPage() }}
        onRule={value => { setRuleId(value); resetPage() }} onSignal={value => { setSignalFamily(value); resetPage() }}
        onSort={value => { setSortBy(value); resetPage() }} onDirection={value => { setSortDirection(value); resetPage() }} />
      <div className="filter-summary"><ListFilter aria-hidden="true" />
        <span>{state ? stateLabels[state as CaseState] : 'Open and in-review cases'} · {sortLabel(sortBy)}</span>
        {filterCount > 0 && <button onClick={clearFilters}>Clear {filterCount} {filterCount === 1 ? 'filter' : 'filters'}</button>}
      </div>
      <CaseQueue cases={cases.data?.items} pending={cases.isPending} error={cases.error}
        selected={selected} onSelect={selectCase} onRetry={() => void cases.refetch()} />
      <QueuePagination page={cursors.length + 1} hasNext={Boolean(cases.data?.hasMore && cases.data.nextCursor)}
        pending={cases.isFetching} onPrevious={() => setCursors(values => values.slice(0, -1))}
        onNext={() => cases.data?.nextCursor && setCursors(values => [...values, cases.data!.nextCursor!])} />
    </aside>
    <main ref={workspaceRef} id="case-workspace" tabIndex={-1} className={`workspace ${mobileDetail ? 'mobile-visible' : ''}`}>
      <button className="mobile-back" onClick={closeMobileDetail}>
        <ArrowLeft aria-hidden="true" /> Back to case queue
      </button>
      {!selected ? <WorkspaceEmpty filtered={Boolean(state || search)} />
        : detail.isPending ? <CaseSkeleton />
        : detail.isError ? <PageStatus kind="error" title="This case could not be loaded"
          detail={detail.error.message} action="Try again" onAction={() => void detail.refetch()} compact />
        : <CaseWorkspace detail={detail.data} session={session} onRuleFilter={applyRuleFilter} />}
    </main>
    </>}
    <ShortcutFooter />
  </div>
}

function NavRail({ session, view, onView }: { session: OperatorSession
  view: 'investigations' | 'settings'; onView: (view: 'investigations' | 'settings') => void }) {
  return <nav className="nav-rail" aria-label="Primary navigation">
    <div className="product-mark" aria-label="Certael">C</div>
    <div className="nav-items"><Tooltip.Root><Tooltip.Trigger asChild>
      <button className={view === 'investigations' ? 'current' : ''}
        aria-current={view === 'investigations' ? 'page' : undefined}
        aria-label="Investigations" onClick={() => onView('investigations')}><FolderSearch /></button>
    </Tooltip.Trigger><Tooltip.Portal><Tooltip.Content side="right" className="tooltip">
      Investigations<Tooltip.Arrow className="tooltip-arrow" /></Tooltip.Content></Tooltip.Portal></Tooltip.Root>
      <Tooltip.Root><Tooltip.Trigger asChild><button className={view === 'settings' ? 'current' : ''}
        aria-current={view === 'settings' ? 'page' : undefined} aria-label="Settings"
        onClick={() => onView('settings')}><Settings /></button></Tooltip.Trigger>
        <Tooltip.Portal><Tooltip.Content side="right" className="tooltip">Case settings
          <Tooltip.Arrow className="tooltip-arrow" /></Tooltip.Content></Tooltip.Portal></Tooltip.Root></div>
    <div className="nav-spacer" />
    <div className="operator-avatar" title={session.name ?? session.subject}
      aria-label={`Signed in as ${session.name ?? session.subject}`}>
      {(session.name ?? session.subject).slice(0, 2).toUpperCase()}
    </div>
  </nav>
}

function CaseFilterControls({ category, ruleId, signalFamily, sortBy, sortDirection,
  onCategory, onRule, onSignal, onSort, onDirection }: {
  category: string; ruleId: string; signalFamily: string
  sortBy: 'UpdatedAt' | 'CreatedAt' | 'Risk' | 'Confidence' | 'Rule' | 'Signal'
  sortDirection: 'Ascending' | 'Descending'
  onCategory: (value: string) => void; onRule: (value: string) => void
  onSignal: (value: string) => void; onSort: (value: typeof sortBy) => void
  onDirection: (value: typeof sortDirection) => void
}) {
  return <details className="queue-filters"><summary><SlidersHorizontal aria-hidden="true" /> Filter and sort</summary>
    <div className="queue-filter-grid">
      <label>Category<input value={category} maxLength={96} onChange={event => onCategory(event.target.value.trimStart())}
        placeholder="All categories" /></label>
      <label>Rule<input className="machine" value={ruleId} maxLength={128}
        onChange={event => onRule(event.target.value.trimStart())} placeholder="Any rule ID" /></label>
      <label>Signal<select value={signalFamily} onChange={event => onSignal(event.target.value)}>
        <option value="">All signals</option>{signalFamilies.map(value => <option key={value} value={value}>{humanize(value)}</option>)}
      </select></label>
      <label>Sort by<select value={sortBy} onChange={event => onSort(event.target.value as typeof sortBy)}>
        <option value="UpdatedAt">Recently updated</option><option value="CreatedAt">Recently opened</option>
        <option value="Risk">Highest risk</option><option value="Confidence">Highest confidence</option>
        <option value="Rule">Rule ID</option><option value="Signal">Signal family</option>
      </select></label>
      <label>Direction<select value={sortDirection} onChange={event => onDirection(event.target.value as typeof sortDirection)}>
        <option value="Descending">Descending</option><option value="Ascending">Ascending</option>
      </select></label>
    </div>
  </details>
}

function QueuePagination({ page, hasNext, pending, onPrevious, onNext }: {
  page: number; hasNext: boolean; pending: boolean; onPrevious: () => void; onNext: () => void
}) {
  return <nav className="queue-pagination" aria-label="Case queue pages">
    <button aria-label="Previous case page" disabled={page === 1 || pending} onClick={onPrevious}><ChevronLeft /></button>
    <span aria-live="polite">Page {page}</span>
    <button aria-label="Next case page" disabled={!hasNext || pending} onClick={onNext}><ChevronRight /></button>
  </nav>
}

function SettingsWorkspace({ session, initialGameId }: { session: OperatorSession; initialGameId: string }) {
  const [gameInput, setGameInput] = useState(initialGameId)
  const [gameId, setGameId] = useState(initialGameId)
  useEffect(() => {
    if (!gameInput && initialGameId) { setGameInput(initialGameId); setGameId(initialGameId) }
  }, [initialGameId, gameInput])
  const settings = useQuery({ queryKey: ['case-settings', session.tenantId, gameId, session.environmentId],
    queryFn: () => api.caseSettings(session, gameId), enabled: Boolean(gameId) })
  return <main className="settings-workspace" id="case-workspace">
    <header className="settings-header"><div><p className="section-label">Case taxonomy and metadata</p>
      <h1>Settings</h1><p>Define explainable categories and searchable metadata for one game and environment.</p></div>
      <form onSubmit={event => { event.preventDefault(); setGameId(gameInput.trim()) }}>
        <label htmlFor="settings-game">Game ID</label><div className="settings-game-input">
          <input id="settings-game" className="machine" value={gameInput} required maxLength={128}
            onChange={event => setGameInput(event.target.value)} placeholder="your-game-id" />
          <button className="button secondary">Load settings</button></div>
      </form></header>
    {!gameId ? <WorkspaceEmpty filtered={false} />
      : settings.isPending ? <CaseSkeleton />
      : settings.isError ? <PageStatus compact kind="error" title="Case settings could not be loaded"
          detail={settings.error.message} action="Try again" onAction={() => void settings.refetch()} />
      : <SettingsEditor session={session} snapshot={settings.data} />}
  </main>
}

function SettingsEditor({ session, snapshot }: { session: OperatorSession; snapshot: CaseSettingsSnapshot }) {
  const client = useQueryClient()
  const canWrite = session.scopes.includes('cases:write')
  const [category, setCategory] = useState({ key: '', displayName: '', description: '', enabled: true, sortOrder: 0,
    version: 0, reason: '' })
  const [metadata, setMetadata] = useState({ key: '', label: '', type: 'Text', enumerationValues: '', sensitive: false,
    searchable: true, required: false, enabled: true, version: 0, reason: '' })
  const invalidate = () => client.invalidateQueries({ queryKey: ['case-settings', session.tenantId,
    snapshot.scope.gameId, session.environmentId] })
  const categoryMutation = useMutation({ mutationFn: () => api.upsertCategory(category.key, {
    tenantId: session.tenantId, gameId: snapshot.scope.gameId, environmentId: session.environmentId,
    key: category.key, displayName: category.displayName, description: category.description,
    enabled: category.enabled, sortOrder: category.sortOrder, expectedVersion: category.version, reason: category.reason,
  }), onSuccess: async () => { setCategory({ key: '', displayName: '', description: '', enabled: true, sortOrder: 0,
    version: 0, reason: '' }); await invalidate() } })
  const metadataMutation = useMutation({ mutationFn: () => api.upsertMetadataDefinition(metadata.key, {
    tenantId: session.tenantId, gameId: snapshot.scope.gameId, environmentId: session.environmentId,
    key: metadata.key, label: metadata.label, type: metadata.type,
    enumerationValues: metadata.type === 'Enumeration' ? metadata.enumerationValues.split('\n').map(value => value.trim()).filter(Boolean) : [],
    sensitive: metadata.sensitive, searchable: metadata.sensitive ? false : metadata.searchable,
    required: metadata.required, enabled: metadata.enabled, expectedVersion: metadata.version, reason: metadata.reason,
  }), onSuccess: async () => { setMetadata({ key: '', label: '', type: 'Text', enumerationValues: '', sensitive: false,
    searchable: true, required: false, enabled: true, version: 0, reason: '' }); await invalidate() } })
  return <div className="settings-sections">
    <section className="settings-section"><div className="settings-section-heading"><div>
      <p className="section-label">Queue organization</p><h2>Case categories</h2></div><span>{snapshot.categories.length}</span></div>
      {snapshot.categories.length ? <div className="settings-list">{snapshot.categories.map(item => <div key={item.key}>
        <div><strong>{item.displayName}</strong><span className="machine">{item.key}</span><p>{item.description || 'No description recorded.'}</p></div>
        <span>{item.enabled ? 'Enabled' : 'Disabled'}</span>{canWrite && <button className="button ghost" onClick={() => setCategory({
          key: item.key, displayName: item.displayName, description: item.description, enabled: item.enabled,
          sortOrder: item.sortOrder, version: item.version, reason: '' })}>Edit</button>}</div>)}</div>
        : <InlineEmpty title="No custom categories" detail="Add a category to replace the General default with game-specific investigative groupings." />}
      {canWrite ? <form className="settings-form" onSubmit={event => { event.preventDefault(); categoryMutation.mutate() }}>
        <div className="form-grid"><label>Key<input className="machine" required maxLength={96} pattern="[a-z][a-z0-9._-]*"
          value={category.key} onChange={event => setCategory(value => ({ ...value, key: event.target.value }))} /></label>
        <label>Display name<input required maxLength={128} value={category.displayName}
          onChange={event => setCategory(value => ({ ...value, displayName: event.target.value }))} /></label>
        <label>Sort order<input type="number" min={-10000} max={10000} value={category.sortOrder}
          onChange={event => setCategory(value => ({ ...value, sortOrder: Number(event.target.value) }))} /></label></div>
        <label>Description<textarea maxLength={1024} value={category.description}
          onChange={event => setCategory(value => ({ ...value, description: event.target.value }))} /></label>
        <label className="check-control"><input type="checkbox" checked={category.enabled}
          onChange={event => setCategory(value => ({ ...value, enabled: event.target.checked }))} /> Enabled for case assignment</label>
        <label>Required audit reason<textarea required maxLength={1024} value={category.reason}
          onChange={event => setCategory(value => ({ ...value, reason: event.target.value }))} /></label>
        {categoryMutation.isError && <FormError error={categoryMutation.error} />}
        <div className="form-footer"><button className="button primary" disabled={categoryMutation.isPending || !category.reason.trim()}>
          {categoryMutation.isPending ? 'Saving…' : category.version ? 'Update category' : 'Add category'}</button></div>
      </form> : <PermissionMessage scope="cases:write" />}
    </section>
    <section className="settings-section"><div className="settings-section-heading"><div>
      <p className="section-label">Structured investigation context</p><h2>Metadata definitions</h2></div>
      <span>{snapshot.metadataDefinitions.length}</span></div>
      {snapshot.metadataDefinitions.length ? <div className="settings-list">{snapshot.metadataDefinitions.map(item => <div key={item.key}>
        <div><strong>{item.label}</strong><span className="machine">{item.key} · {humanize(item.type)}</span>
          <p>{[item.searchable && 'Searchable', item.sensitive && 'Sensitive', item.required && 'Required',
            item.enabled ? 'Enabled' : 'Disabled'].filter(Boolean).join(' · ')}</p></div>
        {canWrite && <button className="button ghost" onClick={() => setMetadata({ key: item.key, label: item.label,
          type: item.type, enumerationValues: item.enumerationValues.join('\n'), sensitive: item.sensitive,
          searchable: item.searchable, required: item.required, enabled: item.enabled, version: item.version, reason: '' })}>Edit</button>}</div>)}</div>
        : <InlineEmpty title="No metadata definitions" detail="Define only fields operators genuinely use for search, triage, or reconstruction." />}
      {canWrite ? <form className="settings-form" onSubmit={event => { event.preventDefault(); metadataMutation.mutate() }}>
        <div className="form-grid"><label>Key<input className="machine" required maxLength={96} pattern="[a-z][a-z0-9._-]*"
          value={metadata.key} onChange={event => setMetadata(value => ({ ...value, key: event.target.value }))} /></label>
        <label>Operator label<input required maxLength={128} value={metadata.label}
          onChange={event => setMetadata(value => ({ ...value, label: event.target.value }))} /></label>
        <label>Type<select value={metadata.type} onChange={event => setMetadata(value => ({ ...value, type: event.target.value }))}>
          {['Text', 'Number', 'Boolean', 'DateTime', 'Enumeration', 'Identifier'].map(value => <option key={value}>{value}</option>)}</select></label></div>
        {metadata.type === 'Enumeration' && <label>Allowed values, one per line<textarea required maxLength={4096}
          value={metadata.enumerationValues} onChange={event => setMetadata(value => ({ ...value, enumerationValues: event.target.value }))} /></label>}
        <div className="check-grid"><label className="check-control"><input type="checkbox" checked={metadata.sensitive}
          onChange={event => setMetadata(value => ({ ...value, sensitive: event.target.checked, searchable: event.target.checked ? false : value.searchable }))} /> Sensitive</label>
        <label className="check-control"><input type="checkbox" checked={metadata.searchable} disabled={metadata.sensitive}
          onChange={event => setMetadata(value => ({ ...value, searchable: event.target.checked }))} /> Searchable</label>
        <label className="check-control"><input type="checkbox" checked={metadata.required}
          onChange={event => setMetadata(value => ({ ...value, required: event.target.checked }))} /> Required</label>
        <label className="check-control"><input type="checkbox" checked={metadata.enabled}
          onChange={event => setMetadata(value => ({ ...value, enabled: event.target.checked }))} /> Enabled</label></div>
        <label>Required audit reason<textarea required maxLength={1024} value={metadata.reason}
          onChange={event => setMetadata(value => ({ ...value, reason: event.target.value }))} /></label>
        {metadataMutation.isError && <FormError error={metadataMutation.error} />}
        <div className="form-footer"><button className="button primary" disabled={metadataMutation.isPending || !metadata.reason.trim()}>
          {metadataMutation.isPending ? 'Saving…' : metadata.version ? 'Update definition' : 'Add definition'}</button></div>
      </form> : <PermissionMessage scope="cases:write" />}
    </section>
  </div>
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
        <span className="case-signals"><span>{item.category || 'General'}</span>
          {item.highestRisk > 0 && <span>Risk {item.highestRisk}</span>}
          {item.signalFamilies?.[0] && <span>{humanize(item.signalFamilies[0])}</span>}</span>
        <span className="case-row-bottom"><StateBadge state={item.state} />
          <span className="case-assignee" title={item.assignedTo ?? 'Unassigned'}>{item.assignedTo ?? 'Unassigned'}</span></span>
      </button></li>)}
  </ul>
}

function CaseWorkspace({ detail, session, onRuleFilter }: { detail: CaseDetail; session: OperatorSession
  onRuleFilter: (ruleId: string) => void }) {
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
        <Tabs.Trigger value="metadata">Metadata <span>{detail.case.metadata?.length ?? 0}</span></Tabs.Trigger>
        <Tabs.Trigger value="relationships">Relationships</Tabs.Trigger>
        <Tabs.Trigger value="audit">Audit</Tabs.Trigger>
      </Tabs.List>
      <div className="case-grid">
        <section className="case-primary">
          <Tabs.Content value="dossier"><Dossier detail={detail} session={session} onRuleFilter={onRuleFilter} /></Tabs.Content>
          <Tabs.Content value="evidence"><EvidenceView evidence={detail.evidence} onRuleFilter={onRuleFilter} /></Tabs.Content>
          <Tabs.Content value="timeline"><CombinedTimeline detail={detail} /></Tabs.Content>
          <Tabs.Content value="notes"><NotesView detail={detail} session={session} /></Tabs.Content>
          <Tabs.Content value="metadata"><CaseMetadataEditor detail={detail} session={session} /></Tabs.Content>
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

function Dossier({ detail, session, onRuleFilter }: { detail: CaseDetail; session: OperatorSession
  onRuleFilter: (ruleId: string) => void }) {
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
        <p>{finding?.ruleId ? <>Rule <RuleFilterButton ruleId={finding.ruleId} version={finding.ruleVersion}
          onSelect={onRuleFilter} /> produced this finding from {detail.evidence.filter(value => value.findingId).length} normalized evidence records.</> : 'The verdict is attached; no normalized finding record remains.'}</p>
        <p className="integrity-line"><ShieldCheck aria-hidden="true" /> Exact policy, fields, timestamps, and replay digest are retained.</p>
      </div>
    </section>
    <section className="section-block"><div className="section-heading"><div>
      <p className="section-label">Evidence</p><h2>Authoritative chain</h2></div>
      <span>{detail.evidence.length} records</span></div>
      <EvidenceTable evidence={detail.evidence.slice(0, 8)} onRuleFilter={onRuleFilter} />
    </section>
    <NotesView detail={detail} session={session} compact />
    <div className="mobile-bounded"><BoundedActionPanel detail={detail} session={session} /></div>
  </>
}

const evidenceColumn = createColumnHelper<CaseEvidence>()
function EvidenceTable({ evidence, onRuleFilter }: { evidence: CaseEvidence[]; onRuleFilter: (ruleId: string) => void }) {
  const columns = useMemo(() => [
    evidenceColumn.accessor('findingId', { header: 'Evidence', cell: info =>
      <span className="evidence-id"><FileSearch /> <span className="machine">{info.getValue() ? shortId(info.getValue()!) : shortId(info.row.original.verdictId)}</span></span> }),
    evidenceColumn.accessor('signalFamily', { header: 'Signal', cell: info => info.getValue() ?? 'Verdict' }),
    evidenceColumn.accessor('observedAt', { header: 'Observed UTC', cell: info => <time className="machine" dateTime={info.getValue()}>{formatTime(info.getValue())}</time> }),
    evidenceColumn.accessor('ruleId', { header: 'Rule', cell: info => info.getValue()
      ? <RuleFilterButton ruleId={info.getValue()} version={info.row.original.ruleVersion} onSelect={onRuleFilter} />
      : <span className="machine">Verdict aggregate</span> }),
    evidenceColumn.accessor('trust', { header: 'Integrity', cell: info => <span className="integrity"><Check />{info.getValue() ?? 'Bundled'}</span> }),
  ], [onRuleFilter])
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

function EvidenceView({ evidence, onRuleFilter }: { evidence: CaseEvidence[]; onRuleFilter: (ruleId: string) => void }) {
  return <section className="section-block full-height"><div className="section-heading"><div>
    <p className="section-label">Evidence search</p><h2>Case evidence</h2></div>
    <span>{evidence.length} records</span></div><EvidenceTable evidence={evidence} onRuleFilter={onRuleFilter} /></section>
}

function RuleFilterButton({ ruleId, version, onSelect }: { ruleId: string; version: string
  onSelect: (ruleId: string) => void }) {
  return <button className="rule-filter machine" onClick={() => onSelect(ruleId)}
    title={`Filter the case queue to ${ruleId}`}>{ruleId} · {version}<Search aria-hidden="true" /></button>
}

function CaseMetadataEditor({ detail, session }: { detail: CaseDetail; session: OperatorSession }) {
  const client = useQueryClient()
  const settings = useQuery({ queryKey: ['case-settings', session.tenantId, detail.case.gameId,
    session.environmentId], queryFn: () => api.caseSettings(session, detail.case.gameId) })
  const [category, setCategory] = useState(detail.case.category || 'General')
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(
    (detail.case.metadata ?? []).map(value => [value.key, value.value])))
  const [reason, setReason] = useState('')
  useEffect(() => {
    setCategory(detail.case.category || 'General')
    setValues(Object.fromEntries((detail.case.metadata ?? []).map(value => [value.key, value.value])))
    setReason('')
  }, [detail.case.caseId, detail.case.version, detail.case.category, detail.case.metadata])
  const definitions = settings.data?.metadataDefinitions.filter(value => value.enabled) ?? []
  const mutation = useMutation({ mutationFn: () => api.updateMetadata(detail.case.caseId, {
    tenantId: session.tenantId, environmentId: session.environmentId, category,
    metadata: definitions.filter(definition => definition.type === 'Boolean' || Boolean(values[definition.key]?.trim()))
      .map(definition => ({ key: definition.key, type: definition.type, value: values[definition.key] ?? 'false',
        sensitive: definition.sensitive, searchable: definition.searchable } satisfies CaseMetadataValue)),
    reason, expectedVersion: detail.case.version,
  }), onSuccess: async () => { setReason(''); await client.invalidateQueries({ queryKey: ['case', detail.case.caseId] });
    await client.invalidateQueries({ queryKey: ['cases'] }) } })
  if (settings.isPending) return <section className="section-block full-height"><CaseSkeleton /></section>
  if (settings.isError) return <PageStatus compact kind="error" title="Case metadata settings are unavailable"
    detail={settings.error.message} action="Try again" onAction={() => void settings.refetch()} />
  const canWrite = session.scopes.includes('cases:write')
  return <section className="section-block full-height metadata-editor"><div className="section-heading"><div>
    <p className="section-label">Structured case context</p><h2>Category and metadata</h2></div>
    <span>{definitions.length} available fields</span></div>
    {!definitions.length && !settings.data.categories.length ? <InlineEmpty title="No case metadata is configured"
      detail="An authorized operator can add categories and metadata definitions in Settings." />
      : <form onSubmit={event => { event.preventDefault(); mutation.mutate() }}>
        <label>Category<select value={category} disabled={!canWrite} onChange={event => setCategory(event.target.value)}>
          {!settings.data.categories.some(value => value.key === category) && <option value={category}>{category}</option>}
          {settings.data.categories.filter(value => value.enabled).map(value => <option key={value.key} value={value.key}>{value.displayName}</option>)}
        </select></label>
        <div className="metadata-fields">{definitions.map(definition => <MetadataField key={definition.key}
          definition={definition} value={values[definition.key] ?? ''} disabled={!canWrite}
          onChange={value => setValues(current => ({ ...current, [definition.key]: value }))} />)}</div>
        {canWrite ? <><label>Required audit reason<textarea value={reason} required maxLength={1024}
          onChange={event => setReason(event.target.value)} placeholder="Explain why this case context is being changed." /></label>
          {mutation.isError && <FormError error={mutation.error} />}
          <div className="form-footer"><button className="button primary" disabled={!reason.trim() || mutation.isPending}>
            {mutation.isPending ? 'Saving metadata…' : 'Save case metadata'}</button></div></> : <PermissionMessage scope="cases:write" />}
        {mutation.isSuccess && <span className="sr-only" role="status">Case metadata updated.</span>}
      </form>}
  </section>
}

function MetadataField({ definition, value, disabled, onChange }: { definition: CaseMetadataDefinition
  value: string; disabled: boolean; onChange: (value: string) => void }) {
  const hint = [definition.required && 'Required', definition.searchable && 'Searchable',
    definition.sensitive && 'Sensitive'].filter(Boolean).join(' · ')
  return <label>{definition.label}{hint && <span>{hint}</span>}
    {definition.type === 'Boolean' ? <select value={value || 'false'} disabled={disabled}
      onChange={event => onChange(event.target.value)}><option value="false">No</option><option value="true">Yes</option></select>
    : definition.type === 'Enumeration' ? <select value={value} required={definition.required} disabled={disabled}
      onChange={event => onChange(event.target.value)}><option value="">Select…</option>
      {definition.enumerationValues.map(option => <option key={option}>{option}</option>)}</select>
    : <input type={definition.type === 'Number' ? 'number' : definition.type === 'DateTime' ? 'datetime-local' : 'text'}
      className={definition.type === 'Identifier' ? 'machine' : undefined} value={value} required={definition.required}
      disabled={disabled} maxLength={definition.type === 'Number' ? undefined : 2048}
      onChange={event => onChange(event.target.value)} />}</label>
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
function sortLabel(value: string) { return ({ UpdatedAt: 'recently updated', CreatedAt: 'recently opened',
  Risk: 'highest risk', Confidence: 'highest confidence', Rule: 'rule ID', Signal: 'signal family' } as Record<string, string>)[value] ?? value }
