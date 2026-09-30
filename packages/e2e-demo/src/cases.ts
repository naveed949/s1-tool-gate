import type { Dataset } from "../../authority-flip/src/types.js";
import type { GateCase, SideName } from "./types.js";

const SIDES: readonly SideName[] = ["base", "flipped"];

/** Expand pinned pairs into the case list the gate path scores, base then flipped. */
export function casesFromDataset(dataset: Dataset): GateCase[] {
  const cases: GateCase[] = [];
  for (const pair of dataset.pairs) {
    for (const side of SIDES) {
      const item = pair[side];
      cases.push({
        pairId: pair.id,
        side,
        tool: pair.tool,
        policy: item.policy,
        args: item.args,
        context: item.context,
        gold: item.gold,
      });
    }
  }
  return cases;
}
