// SPDX-License-Identifier: GPL-3.0-or-later
// checkin mode: the WORKFLOW mints the event, so a dumb curl/HA/Shortcut/ESP
// button is semantically correct without JS/gzip/plan knowledge. Mirrors
// store.js newEvent(): deviceKey "g"+personId, numeric seq, minute-quantized
// ts, 10-minute idempotency window.

export function mintCheckin(PZ, plan, areaId, personId, nowMs) {
  const H = PZ.helpers;
  const area = plan && plan.areas ? plan.areas.find((a) => a.id === areaId) : null;
  if (!area || area.deletedAt) {
    return { error: "unknown-area" };
  }
  if (PZ.model.existsRecent(plan, areaId, personId, nowMs)) {
    return { noop: true };
  }
  const deviceKey = "g" + personId;
  let maxSeq = 0;
  for (const e of plan.events) {
    const parsed = H.parseCompactEventId(e && e.id);
    if (parsed && parsed.deviceKey === deviceKey && parsed.seq > maxSeq) maxSeq = parsed.seq;
  }
  return {
    event: {
      id: H.formatCompactEventId(deviceKey, maxSeq + 1),
      areaId,
      personId,
      ts: Math.floor(nowMs / 60000) * 60000,
    },
  };
}
