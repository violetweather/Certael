import { createServer } from 'node:http'

const now = Date.now()
const iso = minutes => new Date(now - minutes * 60_000).toISOString()
const cases = Array.from({ length: 36 }, (_, index) => ({
  caseId: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
  tenantId: 'qa-tenant', gameId: 'arena', environmentId: 'staging',
  playerSubject: `player_${String(8100 + index)}`,
  title: index % 3 === 0 ? 'Circular transfer pattern across reward accounts'
    : index % 3 === 1 ? 'Repeated authoritative reward redemption'
      : 'Impossible progression sequence',
  summary: 'Signed policy threshold recommends manual review of the authoritative event chain.',
  state: index % 4 === 0 ? 'InReview' : 'Open',
  signedPolicyId: 'economy-review', signedPolicyVersion: '2026.07.1',
  assignedTo: index % 3 === 0 ? 'operator.rivera' : null, version: 3,
  createdAt: iso(220 + index), updatedAt: iso(4 + index), resolvedAt: null,
}))

const detail = item => ({
  case: item,
  evidence: [
    { verdictId: 'verdict-01', findingId: 'finding-01', ruleId: 'circular-transfer', ruleVersion: '4.2.0', signalFamily: 'Economy', trust: 'Authoritative', riskContribution: 0.78, confidence: 0.96, observedAt: iso(12), replayDigest: 'sha256:ec89b6d207798fdb45cf0a9487285b1e', fieldsJson: '{"window":"7d","edgeCount":6,"conserved":true}' },
    { verdictId: 'verdict-02', findingId: 'finding-02', ruleId: 'reward-velocity', ruleVersion: '2.1.3', signalFamily: 'Progression', trust: 'Authoritative', riskContribution: 0.43, confidence: 0.89, observedAt: iso(18), replayDigest: 'sha256:877752e61be77861c4b4121f7f6f09af', fieldsJson: '{"window":"15m","rewards":14}' },
  ],
  notes: [{ noteId: 'note-01', authorSubject: 'operator.rivera', body: 'Transfer sequence aligns with the finding. Awaiting marketplace context before disposition.', createdAt: iso(7) }],
  activity: [
    { activityId: 'activity-01', actorSubject: 'policy:economy-review', activityType: 'CaseOpened', reason: 'Signed manual-review threshold reached', detailsJson: '{"policyVersion":"2026.07.1"}', occurredAt: iso(21) },
    { activityId: 'activity-02', actorSubject: 'operator.rivera', activityType: 'Assigned', reason: 'Queue triage', detailsJson: '{}', occurredAt: iso(8) },
  ],
  actions: [],
})

const send = (response, status, body) => {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  response.end(body === undefined ? '' : JSON.stringify(body))
}

createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1')
  if (url.pathname === '/bff/session') return send(response, 200, {
    subject: 'operator:qa', name: 'Morgan Rivera', tenantId: 'qa-tenant',
    environmentId: 'staging', scopes: ['evidence:read', 'cases:read', 'cases:write', 'cases:act'],
  })
  if (url.pathname === '/bff/antiforgery') return send(response, 200, { requestToken: 'qa-browser-token' })
  if (url.pathname === '/bff/api/cases') {
    const state = url.searchParams.get('state')
    const search = url.searchParams.get('search')?.toLowerCase()
    const filtered = cases.filter(item => (!state || item.state === state)
      && (!search || `${item.title} ${item.playerSubject}`.toLowerCase().includes(search)))
    return send(response, 200, filtered)
  }
  const match = url.pathname.match(/^\/bff\/api\/cases\/([^/]+)$/)
  if (match) {
    const item = cases.find(value => value.caseId === match[1])
    return item ? send(response, 200, detail(item)) : send(response, 404, { title: 'Case not found' })
  }
  return send(response, 404, { title: 'Fixture route not found' })
}).listen(7184, '127.0.0.1')
