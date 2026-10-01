const ownerOptions = ["Atlas", "Beacon", "Cypher"];

const baseRows = [
  [1, "Alpha Watch", "Atlas", false],
  [2, "Beacon Triage", "Beacon", true],
  [3, "Cipher Sweep", "Cypher", false],
  [4, "Delta Review", "Atlas", false],
  [5, "Echo Archive", "Beacon", true],
  [6, "Falcon Relay", "Cypher", false],
  [7, "Gamma Drift", "Atlas", false],
  [8, "Helix Mirror", "Beacon", true],
  [9, "Ion Ledger", "Cypher", false],
  [10, "Jade Signal", "Atlas", false],
  [11, "Kilo Brief", "Beacon", false],
  [12, "Lumen Trace", "Cypher", true],
].map(([id, title, owner, completed]) => ({
  id,
  title,
  owner,
  completed,
  enabled: true,
  permissions: { edit: true },
}));

const generatedRows = Array.from({ length: 48 }, (_, index) => {
  const id = index + 13;

  return {
    id,
    title: `Visual Fixture ${id}`,
    owner: ownerOptions[index % ownerOptions.length],
    completed: id % 3 === 0,
    enabled: true,
    permissions: { edit: true },
  };
});

export const tableFixtureRows = [...baseRows, ...generatedRows];

export const disabledRowFixtureRows = [
  [101, "Dormant Sentinel", "Atlas", false, false],
  [102, "Muted Beacon", "Beacon", false, true],
  [103, "Quiet Ledger", "Cypher", true, true],
  [104, "Staged Rollout", "Atlas", false, true],
  [105, "Fallback Queue", "Beacon", false, true],
].map(([id, title, owner, completed, enabled]) => ({
  id,
  title,
  owner,
  completed,
  enabled,
  permissions: { edit: true },
}));
