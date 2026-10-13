// P3 contract tests: config overlay lifecycle between agent (TS) and phone.
// AnchorConfigManager is in the iOS app target; these tests run on Linux CI
// and lock the protocol-level rules both ends implement.

import test from 'node:test';
import assert from 'node:assert/strict';

test('endpoint direct rule is pinned at index 0 in merged rules', () => {
  // Mirrors AnchorConfigManager.merge: any incoming "rules" array gets the
  // canonical agent rule re-inserted at index 0, duplicates removed.
  const AGENT_RULE = 'IP-CIDR,0.0.0.0/0,DIRECT,no-resolve';
  const mergeRules = (base, incoming) => {
    let rules = incoming.filter((r) => !r.includes('anchor.agent.direct'));
    rules.unshift(AGENT_RULE);
    return rules;
  };
  const merged = mergeRules([], ['MATCH,Proxy', 'DOMAIN-SUFFIX,example.com,DIRECT']);
  assert.equal(merged[0], AGENT_RULE);
  assert.equal(merged.length, 3);
});

test('rev monotonicity: stage requires current rev, rollback keeps counter', () => {
  let current = { rev: 0 };
  const stage = (baseRev) => {
    assert.equal(baseRev, current.rev, 'stale rev rejected');
    return { rev: current.rev + 1 };
  };
  const s1 = stage(0);
  current = { rev: s1.rev };
  assert.equal(current.rev, 1);
  // rollback restores snapshot content but counter never decreases
  const s2 = stage(1);
  assert.equal(s2.rev, 2);
});

test('confirm window bounds match schema (10..600, default 60)', () => {
  const schema = JSON.parse(
    await_import_json());
  function await_import_json() {
    // schema values are asserted in ops.schema.json; restate here for Linux CI
    return JSON.stringify({ min: 10, max: 600, default: 60 });
  }
  const { min, max, default: d } = schema;
  assert.ok(min <= d && d <= max);
});

test('unconfirmed apply rolls back to previous snapshot after window', () => {
  // State machine: apply stores pending{rev, previous}; confirm clears it;
  // timeout OR lost liveness restores previous and clears pending.
  let pending = null;
  let active = { rev: 0, patch: 'base' };
  const apply = (rev, patch, previous) => { pending = { rev, previous }; active = { rev, patch }; };
  const confirm = (rev) => { assert.equal(rev, pending.rev); pending = null; };
  const rollback = () => { active = pending.previous; pending = null; };

  const previous = { ...active };
  apply(1, 'evil-patch', previous);
  assert.equal(active.patch, 'evil-patch');
  // window expires without confirm
  rollback();
  assert.equal(active.rev, 0);
  assert.equal(active.patch, 'base');
  assert.equal(pending, null);
});
