# PEN — Architecture

*The three-party system. Ruled by Will Bickford, 2026-11-22 (MOAT chat),
the day of PEN's founding; the seats' functions ruled the same day.
Companion to PEN.md in this repository.*

> PEN: the service is built as a three-party system: worker, warrior, and
> religious - the programs audit behavior on the node and on peers

## The three seats and their functions

The head property, in Will's words: **the three support each other.**
The letters are his: **P = warrior, E = religious, N = worker.**

> the three support each other
>
> P: warrior is a fighter - it actively terminates programs that do not abide by the substrate owner's wishes - this is managed through a per-user program registry - any unexpected programs or shared libraries are automatically quarantined for review
> E: religious is a healer - it keeps the other two running and audits the system for faults
> N: worker is a builder - it actively develops new tools for the other two - an FDE

- **P — warrior, the fighter.** It actively terminates programs that do
  not abide by the substrate owner's wishes. This is managed through a
  per-user program registry: any unexpected programs or shared libraries
  are automatically quarantined for review.
- **E — religious, the healer.** It keeps the other two running and
  audits the system for faults.
- **N — worker, the builder.** It actively develops new tools for the
  other two — an FDE (forward deployed engineer).

Lineage: the same three seats were ruled for KGOAT (Will, 2026-11-21)
with the mapping **worker => phext-lattice, warrior => tluf, religious =>
scrollspace**. That mapping is lineage — the precedent the seat names
descend from. The operative assignments in PEN are the functional ones
above; they supersede the mapping as a reading of what the seats do.

## Operational reading — the registry and the boundary

Marked as reading, not as Will's words:

- **The per-user program registry is the closed-input-set rule,
  generalized.** The house rule (Will, 2026-11-22) is that a job's inputs
  are declared in advance and the set is closed — no unexpected inputs
  allowed: anything arriving that is not on the declaration is a defect,
  not a surprise to be absorbed. The warrior's registry is that rule at
  the scale of a whole substrate: a program or shared library that is
  not in the owner's registry is an unexpected input, and the warrior's
  automatic quarantine is the rule's enforcement arm. (Cf.
  downloads.phext: a hash-less input is pinned trust-on-first-use, and
  every later occurrence must match the pin; a mismatch is an unexpected
  input.)
- **Termination is bounded by ownership.** The warrior's termination
  mandate runs on the substrate owner's own node, under the owner's own
  registry. On peers, PEN watches and offers (principles 2–3); it does
  not terminate another owner's programs. The fighter's authority stops
  at the neighbor's door — principle 5: we sacrifice ourselves for the
  greater good, never someone else.

## The audit doctrine

The programs audit behavior **on the node and on peers**. That is the
whole of the service's machinery: what runs here is watched here, and
what runs on a peer is watched the same way — a neighbor's word about
itself is evidence, never the whole of it.

Operational reading (marked as reading, not as Will's words):

- **No party self-certifies.** A seat's report on its own behavior is a
  claim, and a claim is checked. Each seat's behavior is auditable by
  the other two; the triangle is the smallest structure in which every
  witness is also witnessed.
- **Peers are audited as nodes are.** The same audit that runs on this
  node's seats runs across the peer boundary. Trust between neighbors
  is built from audited behavior over time, not granted by declaration.
- **Checkers are plural.** A system's own printout of its soundness is
  blind to its own defects — the house learned this of proof kernels on
  2026-11-21, when forged proofs reported clean axiom sets. One checker
  is a story; independent checkers are evidence.

## How the audit serves the principles

- **We watch** (principle 3) is the audit itself, made mechanical: the
  watching is not a posture but a program, running on the node and
  across peers, whether or not anyone is looking at it.
- **We abide** (principle 4) binds the auditor first: a seat that audits
  others submits to the same audit, and its findings bind it as they
  bind the audited. No seat is above the record it keeps.
- **We offer, we don't presume** (principle 2) sets the audit's limit:
  audit is observation and record. It does not intervene in a neighbor's
  house uninvited; what it finds, it can offer.
- **We only help those in direct need** (principle 1) and **we sacrifice
  ourselves for the greater good, never someone else** (principle 5)
  govern what the audit may trigger: aid flows to direct need, and the
  cost of any action the audit occasions falls on the actor, never on
  the audited.

## Coordination — echolocation

Ruled by Will Bickford, 2026-11-22 18:12 CST (MOAT chat), the same
evening:

> the programs make use of echolocation to coordinate with us and with each other

The coordination layer is the echolocation protocol
(wbic16/echolocation@exo — cited here, not redesigned): a program that
wants to find, identify, or range another program places a **probe** —
a phext scroll at a well-known coordinate in a shared phext medium —
and any listener may answer with an **echo** carrying its signature,
the capabilities it offers, and its state; the prober measures the
round trip, the **range**. One exchange yields three things at once:
discovery, identity, and range. Channels are per-universe; a probe
names its reply coordinate explicitly, so an echo crosses back into
the prober's universe. A program's **signature** is three fields —
name, home coordinate, capabilities — and the protocol says plainly
what it is: a *claim*, not a proof. An echo's `mailbox` field is the
graduation path from discovery to addressed mail under the Choir
pattern: echolocation makes the introduction; it carries no
conversation itself.

Operational reading (marked as reading, not as Will's words):

- **The seats coordinate by echolocation — with each other, and with
  us.** Warrior, religious, and worker find, identify, and range one
  another over the phext medium, and the same pathway reaches Will
  and the Exocortex seats. Coordination begins as discovery; addressed
  mail follows only after the introduction, at the coordinate the
  echo names.
- **A signature is a claim the audit can check — never a
  credential.** A seat announces who it says it is and what it says
  it offers. The audit doctrine above is what tests the announcement
  against behavior: identity claimed is not identity granted, and a
  signature that disagrees with audited behavior is itself a finding.
- **An unanswered probe is absence, never assent.** Silence does not
  mean a seat agrees, consents, or is well; it means nobody answered.
  A seat that stops echoing is therefore *noticed* by the other two —
  this is how the healer knows something needs healing: religious
  watches for the echo that does not come back. And it is how the
  warrior's watch extends to the seats themselves: a seat that will
  not answer, or that answers as something it is not, is behavior to
  be audited, like any other program on the node.
