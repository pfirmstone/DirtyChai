# Requirements: Multi-Node Host Board for Untrusted Proxies

Status: draft requirements, not a design. Nothing here is implemented or evaluated.
Companion to `SECURITY_MODEL.md` sections 14.1 to 14.5 and `PROCESS_ISOLATION.md`.

## 1. Purpose and scope

A client that downloads a smart proxy from an untrusted server runs that proxy on separate
hardware (`SECURITY_MODEL.md` section 14.3). This document sets requirements for one board that
carries several independent compute nodes, an Ethernet switch, a management controller and a
per-node watchdog, so that several such hosts can be built economically.

In scope: the board's electrical and logical isolation, power control, boot, and network
enforcement. Out of scope: the JVM, the launcher software, the policy, and the choice of a
particular vendor part.

## 2. Assumptions

- One node serves one remote server's SPIFFE ID at a time (section 14.4). A node is never shared
  between principals concurrently. It is reused between principals only after a power cycle and a
  network reimage.
- The attacker is code in a proxy JVM on a node: it can run arbitrary Java under the JVM's
  permissions, and it may later gain native code execution if the JVM is broken.
- The attacker is not assumed to have physical access to the board.
- Nodes use in-order application cores only (`SECURITY_MODEL.md` section 14.5, first item).
- The management controller, the switch and the uplink are trusted. A compromise of any of them
  breaks isolation for every node on the board, so they are held to a higher standard than a node.

## 3. Requirements

Each requirement has an identifier for use in reviews and acceptance tests.

### 3.1 Compute nodes

- **N1.** Each node is a complete small computer with its own cores, DRAM and storage. No DRAM,
  cache or storage is shared between nodes.
- **N2.** Every application core on every node is in-order. If the chosen SoC has an out-of-order
  cluster, it must be disabled in firmware, and that must be verified, not assumed.
- **N3.** Nodes are soldered down (for example an OSM solder-down module or a directly mounted
  SoC). The consequence is that a failed node is replaced by replacing or reworking the board, so
  the node count per board is kept small (suggested 4 to 8; see Y5 for the 2U chassis).
- **N4.** Each node has secure boot enabled with keys fused at manufacture, and no unsigned boot
  path. A part without ROM secure boot is accepted only under boot case C in section 3.6.
- **N5.** Each node has enough memory to hold its root image in RAM, the JDK, a JVM with its JIT and
  GC, and its working data. Inline ECC, if used, reduces the usable capacity. The minimum is a
  decision for the deployment and is measured, not assumed (a trimmed `jlink` image is much smaller
  than a full JDK, and a shared CDS archive in RAM can serve the JVMs of one principal).
- **N6.** A node runs from a root image held in RAM and has no writable persistent storage in normal
  operation. The only persistent storage is a small boot flash (the first-stage bootloader, and the
  image under boot case D) that is write-protected in hardware against code running on the node,
  or restorable by the controller on every cycle (boot case C). Most SoC boot ROMs cannot boot from
  the network directly, so a small boot flash is expected; this should be confirmed per SoC.

### 3.2 Power and kill

- **P1.** Each node has its own regulator and its own power switch (load switch or regulator
  enable). A fault or brownout on one node does not reset another.
- **P2.** The power switches are driven only by the management controller (section 3.4). No node can
  drive, read the state of, or delay any switch.
- **P3.** Cutting power must work whatever the node's software is doing. It must not depend on the
  node's operating system, JVM or network.
- **P4.** After a cut, the controller holds the node off for a fixed minimum before restoring power,
  so that the node's capacitors discharge. The value is chosen and measured per board.
- **P5.** Board input power is a DC input or a high-power PoE supply (802.3bt) sized for the maximum
  draw of all nodes plus the switch and controller, with margin. The per-node draw is measured.

### 3.3 Watchdog

- **W1.** Each node has a hardware watchdog that is external to the node's SoC and cannot be
  disabled by software running on the node.
- **W2.** The watchdog escalates: first a reset pulse to the node, then, if the node does not
  recover within a set window, a full power cut through P1. A reset alone does not clear DRAM, so it
  is never sufficient between principals.
- **W3.** The watchdog is fed only by trusted code. The feed path must not be satisfiable by proxy
  code: a proxy that spins or stalls must not keep the watchdog alive. The signal fed is a liveness
  and lease indication from the trusted launcher, not a bare heartbeat from a node.
- **W4.** The watchdog window must allow for scheduling delay on the cores assigned to the node
  (`SECURITY_MODEL.md` section 14.2, lease bullet) so that a loaded but healthy node is not killed.
- **W5.** Every reset and power cut is logged by the controller with a reason.

### 3.4 Management controller

- **M1.** A small microcontroller, separate from every node, owns the power switches, the watchdogs
  and the switch configuration.
- **M2.** Its firmware is signed, with a locked and authenticated update path. Its debug interface is
  disabled or fused in production.
- **M3.** Its management interface is not reachable from any node port. It is reachable only from
  the trusted uplink, requires authentication, and logs every command.
- **M4.** Only the trusted launcher may request a power cycle or reimage of a node. A node cannot
  request its own cycle in a way that selects a principal or an image.
- **M5.** The controller does not parse node-supplied data beyond a minimum fixed-format channel, if
  one exists at all.

### 3.5 Ethernet switch

- **S1.** The switch is managed and enforces per-node isolation: each node port is in its own private
  VLAN or isolated port group and cannot reach another node's port.
- **S2.** Each node can reach only its allowed destinations: the remote server for its current
  principal, and the boot server for its own image. Enforcement is an egress allowlist applied by
  the controller.
- **S3.** MAC addresses are pinned per port. Spanning tree, LLDP, discovery protocols and any other
  protocol that the board does not use are disabled on node ports.
- **S4.** Rate limits and storm control apply on node ports, so a hostile node cannot flood the
  uplink or the controller.
- **S5.** The switch's management interface is only reachable from the controller (M3).
- **S6.** Hostile frames from a node are treated as an attack on the switch, so the switch is
  selected for ACL and rate-limit support and its configuration is under change control.

### 3.6 Boot and reimage

- **B1.** The root image comes from one of the boot cases below. The boot server, where one is used,
  is reachable only on that node's isolated path (S2), and the choice of case is recorded per
  platform.
- **B2.** The image is rebuilt or reset between principals, with the root in RAM and no persistent
  writable state carried over.
- **B3.** A power cycle does not clear flash, eMMC or fuses. Verified boot (N4), or restoration of
  the boot media by the controller (case C), is what prevents a persistent compromise.
- **B4.** The time for restore, power negotiation, boot and image load is measured and recorded. It
  bounds how fast a node can be reused. The boot server's link bandwidth is part of the figure,
  since all nodes may boot together after a power event (measure a full-unit boot).
- **B5.** The network is never the root of trust. A network-fetched image runs only if it is verified
  by a bootloader that is itself trusted (case A or C), or it is delivered by the controller over a
  private local link (case D). Signed images carry rollback protection.

Boot cases, in order of preference:

- **Case A.** The SoC's ROM verifies the first-stage bootloader (secure boot, keys fused), and that
  bootloader verifies a signature on the kernel and root image fetched over the network, with
  rollback protection.
- **Case B.** The ROM verifies the first stage, but the bootloader cannot verify the network stage.
  Add signature verification to the bootloader if its loader supports it. If it cannot, use case D.
- **Case C.** The SoC has no ROM secure boot. The controller owns the node's boot media while the
  node is off or held in reset, writes the first-stage bootloader on every cycle (or reads it back
  and rewrites only on a mismatch, logging the mismatch), and releases the node only after
  verifying it. A restored bootloader is trustworthy, so it may embed a public key and verify
  signed network images, which completes the chain. Conditions:
  - a hardware mux or isolation gives the controller exclusive access to the boot media while it
    programs it;
  - all persistent state on the node is reachable by the controller, or shown unable to hold a
    compromise: other flash, eMMC, attached device firmware, and fuses. Every fuse that software on
    the node can blow is listed and its consequence assessed;
  - the golden image has no write path from any node and is updated only by the trusted launcher
    through the controller's signed firmware (M2);
  - flash write-cycle endurance is budgeted for the expected number of reflashes.
- **Case D.** The controller delivers the whole image to the node over a private local link (for
  example into eMMC or SPI flash while the node is held in reset), so no boot server or network
  path is involved. This costs on-board image storage, an update path for it, and write time per
  cycle.

### 3.7 Attack surface

- **A1.** Node-side interfaces not needed for operation are not fitted: no USB host, no HDMI or
  display, no wireless, no audio, and no exposed debug headers.
- **A2.** A node's serial console, if fitted, is disabled in production or reachable only through
  the controller.
- **A3.** The only ingress to a node from outside the board is the isolated Ethernet path (S1, S2).

### 3.8 Physical

- **Y1.** The assembly is a 2U rack unit (19 inch, 88.9 mm high). 2U is chosen over 1U because it
  takes larger, slower and quieter fans, taller heatsinks, and standard redundant supplies that are
  easier to source, at the cost of lower compute density. Component height, heat sinks and
  connectors must fit within the usable interior height, and cooling is front-to-back airflow
  through the chassis. Operating temperature and airflow are stated explicitly, and a module's
  temperature rating is checked against its datasheet, not a reseller's page.
- **Y2.** The board carries EMC and safety certification appropriate to its market, which is a
  separate project cost.
- **Y3.** Rack power is a DC input (for example 12 V or 48 V) or a dual-redundant supply feeding the
  board, since PoE is unlikely to supply a whole 2U unit. If PoE is used, it is 802.3bt and
  the budget is stated per P5.
- **Y4.** External connectors on the front or rear panel are limited to: the Ethernet uplink (or
  uplinks), power, and a management connection to the controller that satisfies M3. No node-side
  connector is exposed on the panel (A1, A2, A3).
- **Y5.** A 2U unit with large heatsinks and fans holds few nodes per row, and may still hold more
  nodes than one board comfortably should carry. Because a board
  fault, or a compromise of the controller or switch, affects every node on that board, prefer
  several smaller boards in the chassis, each with its own controller and switch, to a single large
  one. The count is a decision for the deployment and is limited by power budget (P5), switch port
  count and cooling.
- **Y6.** The chassis has a tamper indication (for example an intrusion switch) read by the
  controller and logged. Physical attacks are otherwise out of scope (section 4).
- **Y7.** Chassis layout: a single flat board with each node's heatsink on top, standard redundant
  hot-swappable power supplies at the rear, fans across the front drawing air through the chassis,
  and a lid that lifts off for service. The board takes a single DC rail from the supplies (for
  example 12 V), from which the per-node regulators (P1) are derived.
- **Y8.** The controller (M1) monitors each supply and each fan: supply presence and fault,
  fan tachometer, and per-node temperature. It logs faults, and on loss of cooling or of both
  supplies it powers nodes off in an orderly way instead of leaving them running. A single supply or
  fan failure is reported and does not stop service.
- **Y9.** Lid removal is read by the intrusion switch (Y6). Service with the lid off is a logged
  event. Because nodes are soldered, service means replacing the board, supplies or fans; there is
  no field-replaceable node.
- **Y10.** Heatsinks are fixed to the nodes and do not connect one node's thermal path to another's.
  Airflow is shared by necessity, and nodes are not assumed thermally isolated from one another.
- **Y11.** The nodes sit in a row across the front of the board, immediately behind the fans, so
  that each receives fresh intake air and no node is cooled by air another node has heated.
  Heatsink fins run parallel to the airflow. The switch, controller and regulators sit behind the
  nodes and are rated for the warmed air they receive. The distance between fan and heatsink is
  chosen so that the airflow across each heatsink is even, since a fan close behind its outlet
  leaves a dead zone over its hub. The cooling margin is checked by measurement under full load on
  every node, including with one fan failed (Y8). Rear panel connectors carry the Ethernet uplink,
  power and management connection (Y4), since the front is occupied by fans and intake.
- **Y12.** Each node has its own heatsink, not shared with any other node (Y10), and its own two
  fans, so that one fan failure leaves that node cooled by the other. Each fan has its own
  tachometer read by the controller (Y8). The fan count is two per node, so the number of nodes
  per row is bounded by the 2U interior width divided by the fan width: with 80 mm fans, a single
  row across a 19 inch chassis fits about five fans and therefore two nodes; with 60 mm fans about
  seven fans and three nodes. These are rough figures from the nominal width, not a chassis
  drawing. More nodes need a second rank of fans, smaller fans, or a second board (Y5). The
  electrical power of the fans is counted in the budget (P5).
  A node whose two fans have both failed is powered off by the controller (Y8).
- **Y13.** Heatsink size takes priority over fan speed. Fans are low-power and low-speed, chosen
  for efficiency and low noise, and the heatsinks are as large as the 2U height and the node pitch
  allow, with fin spacing wide enough that a low-pressure fan can move the air through them. The
  consequence is that the heatsink footprint, not the module size, sets the node pitch and so the
  number of nodes per board (Y5, Y12), and that fan power (P5) is lower than a
  high-speed 1U design would need. The airflow each heatsink needs is calculated from the node's maximum dissipation and
  verified by measurement (Y11).

### 3.9 Caddy architecture (proposed alternative to 3.8 Y5, Y7 to Y13)

The nodes are carried in 3.5 inch hot-swap drive caddies in a commodity rackmount storage
chassis, with the switch and controller outside the caddies. This is an alternative to the single
flat board of 3.8. Where it is adopted, C1 to C10 replace Y5 and Y7 to Y13. The chassis dimensions
and bay layout are not verified (section 5). A picture of a 24-bay 4U case shows 4 caddies across
by 6 high, with a perforated SAS-expander backplane; the listing does not state either. A picture
of a second 4U case (a 20-bay model, 4 across by 5 high, with a front panel above the top row)
shows one separate backplane strip per row, each with its own power and mini-SAS connectors,
mounted upright across the row. So per-row boards are normal in this class of chassis. Those
mounting provisions are for upright boards, so a flat row board (R1) needs its own brackets, which
is expected to be inexpensive custom sheet metal but is not verified on a real cage.

Variants considered. The cooling and switch placement differ; C1 to C10 apply to all.

- **V1.** Front-loading cages with one full-height backplane carrying the switch. Simplest
  mechanically, but the backplane crosses the air path.
- **V2 (proposed).** Front-loading cages with one row board per row of caddies (R1 to R8). Chosen
  as the working variant because no board crosses the air path and a board fault is limited to
  one row. Nothing is decided until T-C1 and T-C2 (section 7) are run.
- **V3.** Top-loading vertical cage with a floor plane, as in the Sun Fire X4500 (recalled, not
  checked). About 15 to 16 nodes per row at about 26 mm pitch in 4U (estimate); needs rails and a
  custom case. Not pursued unless V2 fails.
- **V4.** Front-loading cages with a network port on the front of each caddy and an external
  switch. Rejected as the main variant: it exposes 24 node ports on the panel (A1 to A3, Y4) and
  puts 24 patch cables across the intake. Row boards (R5) reduce this to six uplinks at the rear.
- **Cooling fallback.** A supply plenum and exhaust plenum in a custom 5U case, cooling nodes in
  parallel. Adopted only if T-C1 shows the rear nodes too hot. A rough estimate (24 nodes at 5 W,
  80 CFM effective flow, air properties assumed) gives about 2.6 K total air rise, so it is not
  expected to be needed. Push-pull fan banks need per-fan tachometers and backdraft dampers.

- **C1.** One caddy carries exactly one node: one SOM on a node board that fits the 3.5 inch drive
  envelope (about 101.6 x 147 x 26 mm, unverified). A caddy never carries two SOMs, so pulling a
  caddy never removes more than one SPIFFE ID domain (section 14.4).
- **C2.** The node board carries only the SOM, its power conditioning, the board connector and
  the presence pin. The Ethernet switch, the management controller, the per-slot power switch
  (P1 to P5) and the watchdog (W1 to W5) are on the backplane or row boards (V1 or V2), outside
  anything the proxy can reach.
- **C3.** The backplane or row board is a custom part, not the chassis's drive backplane, which
  carries only SATA or SAS data and power. Any controller, power supply, fan board or front-panel wiring
  supplied with the chassis is untrusted and not used. Only the sheet metal, drive cages and caddy
  trays are taken from the chassis.
- **C4.** The node connector is physically keyed so a node cannot be inserted into a real drive
  backplane, nor a drive into a node slot. Whether Ethernet is carried over drive-style connector
  pins (for example SGMII) is not established and is not assumed.
- **C5.** Each slot has its own hot-swap power path with inrush limiting and overcurrent
  protection, switched by the controller (P1). A slot is powered only when its presence pin is
  asserted and the controller commands it.
- **C6.** A caddy has a lock. Removal is read from the presence pin and logged by the controller
  (Y6). Pulling a caddy is a logged event, and a caddy inserted after removal is treated as an
  unknown node and reimaged before use (B1 to B5).
- **C7.** Each caddy is its own front-to-back air lane, with cool air entering at the front and
  the chassis fan wall behind the backplane. Heatsink height is limited to what fits in the caddy
  (about 12 to 15 mm above the board, an estimate). Whether that is enough for the chosen SOM is
  checked by thermal calculation and then measurement, at full load with one fan failed.
- **C8.** The fan wall is replaceable with standard fans, and its redundancy is N+1 rather than
  two per node. The controller reads each fan's tachometer and each slot's temperature (Y8), and
  powers a slot off when its temperature limit is exceeded. This replaces Y12's two fans per node.
- **C9.** Nodes share the backplane power rails. Coupling between nodes through those rails is
  added to the covert-channel list in `SECURITY_MODEL.md` and is not assumed negligible.
- **C10.** The backplane or row-board mounting is designed to the cage geometry, connector
  positions and bay pitch of one named chassis model. A change of chassis model changes the
  mounting; under V2 the row board itself is unchanged (R6).
- **C11.** Node connector. The male side is on the row board (or backplane): its front edge
  carries the gold fingers. The node board carries an edge-mount receptacle whose slot opens
  toward the rear of the caddy. This is chosen as the cheaper design, and so that a node board
  has no fingers and cannot be plugged into a PCIe slot. The wearing spring contacts go with the
  replaceable node. The connector family is not fixed: a PCIe-style card-edge receptacle is the
  working candidate, used only as a mechanical and electrical part with its own pinout. The
  fingers' keying notch must not match a PCIe card, and a drive cannot mate with the fingers (C4).
  The fingers are hard-gold plated on a board of the thickness the receptacle expects. Because
  the fingers on an empty slot are exposed, a slot is de-energised whenever presence is not
  asserted (C5), and presence mates last. The receptacle's rated mating cycles, finger length
  staggering and insertion tolerance are checked against the datasheet and by T-C2. Requirements:
  - Ethernet: two links (H2), each four pairs of 1000BASE-T, eight pairs in all, with a PHY and
    magnetics on each side. SGMII is used only if the switch ports are known to support it.
  - Power: 12 V on at least three pins with matching grounds, sized for the node's maximum draw
    with margin. The node board derives its own rails.
  - Sideband: presence, power-good or reset, watchdog heartbeat, boot select, and spare pins. With
    two links the contact count is about 40 (an estimate), so the 36-way size no longer fits and
    a 64-way part is expected.
  - Sequencing: grounds mate first, then power, then signals, and presence mates last and breaks
    first.
  - Node-to-controller lines are hostile input. They are plain digital levels read by hardware
    (the watchdog and presence logic), not a protocol parsed by controller firmware. Any console
    from the node is one-way logging into a buffer the controller does not interpret, or is
    omitted. Controller-to-node lines (reset, boot select) are outputs only.
  - Rated mating cycles need only cover service events, since nodes are reimaged by power cycle
    and not by removal (B1 to B5). The expected life count is an estimate and is stated in the
    design.

#### Row boards (V2)

Each row of four caddies has a flat board behind it, in the plane of the air flow, with
forward-facing edge connectors (geometry confirmed by the project lead). The board is expected to
mount to the caddy frame (the cage) directly, which is expected to be straightforward but is not
yet checked on a real cage (R7, T-C2).

- **R1.** One row board per row of caddies carries four node connectors, lying flat behind the row
  and parallel to the airflow, so that no board crosses the air path. Component and connector
  height behind the caddies is limited so the air exit stays open. The obstruction is measured
  against a no-board baseline (T-C1).
- **R2.** Each row board carries two five-port switches, one per network (H2), each with four node
  ports and one uplink. Node ports must not forward to one another (S1). Preferably this isolation is fixed in hardware, for
  example by pin straps, so the row switch has no firmware. An unmanaged switch without port
  isolation is not acceptable. Whether a five-port part with hardware-fixed isolation exists is
  open (section 5).
- **R3.** Per-node destination policy (allowed origin addresses, rate limits) is enforced
  upstream of the row boards, by the managed switch in the chassis (H2), not by the row switch,
  so row boards stay simple. That switch meets S1 to S6.
- **R4.** Per-slot power switching, reset, presence, console and boot-select lines are on the row
  board and driven by one central controller over a control bus. A row board carries no firmware
  of its own where practicable, so the trusted firmware is the controller's alone (M1).
- **R5.** Each row has one uplink on the host network, to the host, and one on the egress network,
  to the egress switch (H2): five or six of each, by chassis. No node port is on the front or
  rear panel, so A1 to A3 and Y4 hold for nodes. The controller has its own management
  connection, on a network no node port can reach (M3).
- **R6.** The row board is chassis-independent. The chassis sets the row count (for example three
  rows for a 2U 12-bay case, five for a 4U 20-bay case and six for a 4U 24-bay case). Only the mounting and cage alignment
  are chassis-specific (C10).
- **R7.** Each row board is located to the cage's caddy guides, and the connectors float or are
  guided, to absorb the tolerance chain across separately mounted boards. The tolerance of the
  chosen chassis is checked on a sample (T-C2).
- **R8.** A row board fault affects at most four nodes. The controller can power a row off
  independently and monitors each row's uplink.

### 3.10 Integrated host (V2)

The trusted host is installed in the rear of the same chassis, behind the fan wall (per the
project lead), probably a single-socket Xeon or AMD server board. This makes the unit one
appliance: a JGDMS and DirtyChai client and service host plus up to 20 or 24 isolated nodes.

- **H0.** The nodes host only the proxies that remain smart proxies. A code-free proxy (a dynamic
  proxy, DER data and a bounded expression; `SECURITY_MODEL.md` section 14.1) has no mobile code
  and needs no node. How many services remain smart proxies is not known, and sizing follows it
  (section 5). The row boards are modular (R6), so one or two rows can be built first.
- **H1.** The host runs the trusted client and service host and treats everything received from a
  node as hostile data (`SECURITY_MODEL.md` section 14.1). The host's own firmware (UEFI, BMC,
  and the CPU vendor's management engine) is part of the trusted base and is outside this
  document. Admission control (section 14.4) runs on the host and fails closed when no node is free.
- **H2.** Each node has two Ethernet links, each on its own network (project lead's proposal).
  The host network joins each node to the host through the row boards and has no connection to
  any outside network. The egress network joins each node to its origin server through a managed
  switch in the chassis and the egress uplink, and the host has no port on it. Node-to-node
  traffic is denied on both networks (S1). The controller programs the egress switch's per-node
  destination rules (R3), and that switch's management interface is unreachable from node ports
  (S5). The host does not route node traffic. A node's operating system must not forward between
  its two links, and the host treats every node as hostile regardless (H1), since a compromised
  node could bridge the two networks.
- **H3.** A node connects directly to its own origin server over the egress network, not through
  the host. A proxy therefore cannot observe delays caused by host load in its own traffic, and
  the origin server sees the node's egress address and not the host's. The host contacts only the
  lookup service, never the service's server (H9), so the host's address is visible to the lookup
  service and not to the origin, unless one party runs both. A compromised node can relay between
  the two networks, so the origin
  could learn the node's private host-network address, which is not routable outside. The nodes
  share the egress uplink, so shared-queue timing between nodes remains (section 4), reduced by
  per-node rate limits and queueing. The host's own responses to a node's calls remain a latency
  channel, which the clock granularity (`SECURITY_MODEL.md` section 11.7) addresses and this
  layout does not.
- **H4.** The node controller (M1) is independent of the host and of its BMC. The host commands it
  (assign a node to a SPIFFE ID, reimage, kill) over a dedicated authenticated link that no node
  can reach. If the host's heartbeat is lost, the controller powers all nodes off.
- **H5.** The host serves signed boot images to the nodes over the row networks (B1 to B3) and is
  the only boot server. Images for boot case D are held by the controller.
- **H6.** The host's BMC and management port are on a management network separate from the node
  networks and from the uplink (M3). Host ports not needed in service (USB, video) are disabled
  or covered, and no front-panel connector is wired to a node (A1 to A3, Y4).
- **H7.** The host and the nodes share the supplies. They are sized for the host's peak plus all
  nodes plus the fans, with one supply failed. Per-slot switches and per-node regulators (P1, C5)
  isolate the nodes from host load changes, but coupling through shared rails and supplies stays
  on the covert-channel list (C9) and now includes host-to-node as well as node-to-node.
- **H8.** The host sits behind the fan wall in air the nodes have warmed. T-C1 is repeated with the
  host at its peak load. Fan control belongs to one owner (the controller, with the host's CPU
  temperature as an input), never to both the controller and the host's BMC.
- **H9.** Proxy flow. The host looks the service up in a lookup service and receives the proxy in
  marshalled form. It keeps the proxy marshalled, as opaque bytes, and sends it to a node, where it
  is unmarshalled, its classes are loaded, and it connects to its service's server over the egress
  network (H3). The host never unmarshals the proxy or loads its classes, and never contacts the
  service's server. The host invokes calls remotely on the proxy over the host network. They arrive
  at the proxy through the node's own dispatcher, so the proxy sees them as local calls and not as
  coming from the host's address. The arrival times of those calls still reflect the host's
  schedule, which is part of the latency channel in H3.

### 3.11 Legacy session-host node (a possible variant, not decided)

Raised by the project lead: legacy and web applications cannot all be replaced, so they could be hosted on their old platforms and their
display accessed remotely. The lead said "if you like" to recording it; nothing here is a decision. Everything below is design intent
from the conversation, not reviewed.

- **L1.** A session-host node runs one legacy application or browser on its original platform, for **one trust domain**, and the user sees only its
  display. The client never executes the application's code.
- **L2.** Legacy platforms are mostly x86 and often unpatched, so the Arm in-order modules of 3.1 cannot host them. A session-host node is a
  **different node class**: an x86 module or small server, or slow emulation. The in-order rule (`SECURITY_MODEL.md` 14.5) does not apply to it, because
  one trust domain per node keeps its timing exposure inside that node.
- **L3.** The same control plane applies: identity (SPIFFE), policy on which sessions a client may start, leases, power cut and reimage from outside
  the node, and egress rules (H2, H3, P1 to P5, B1 to B5). Reimage between trust domains is required.
- **L4.** The remote-display path is the attack surface. It carries pixels only, where possible; any structured channel (clipboard, files, audio,
  printing) is off by default and needs an explicit guard. The viewer treats everything from the node as hostile input.
- **L5.** User input is mediated by the trusted side (the client-device idea in the conversation, not recorded elsewhere): input goes only to the
  intended session, and secrets are never forwarded to it.
- **L6.** Open: licensing for old operating systems, latency, audio and printing, how long each old platform can be kept alive, and whether this node
  class is built at all.

## 4. What the board does not address

- **Timing channels between nodes through shared infrastructure** (power rails, the switch's
  buffering) are reduced by per-node regulators and port isolation (P1, S1) and are not eliminated.
- **A compromised kernel on a node** is contained by network isolation and power control, not
  prevented. This is why secure boot (N4) and reimage (B2, B3) are required.
- **Cache attacks inside one node's cluster** between cores of the same principal are accepted
  (`SECURITY_MODEL.md` section 14.4: a board's cores are one trust domain).
- **Physical attacks** on the board are out of scope.

## 5. Open questions

- Does the chosen module support network boot, and with what boot-loader trust model?
- Does the chosen SoC have an IOMMU that restricts DMA for every bus-mastering peripheral?
- What is the real per-node and per-board power draw under load?
- Can an out-of-order cluster on the chosen SoC actually be disabled and the disabling verified?
- Which switch IC gives ACLs, private VLANs, rate limiting and a management interface that can be
  made unreachable from node ports?
- How are fused secure-boot keys provisioned and recorded at manufacture, and who holds them?
- What is the replacement and recovery procedure when a soldered node fails?
- Which boot case (section 3.6) applies to the chosen SoC and bootloader? Does its bootloader
  support signature verification of a network-fetched image, and rollback protection?
- Does the SoC's boot ROM support a boot source that the controller can program independently of
  the node (case C), and can software on the node blow fuses that change boot configuration?
- How much RAM does a RAM-resident root plus JDK, JVM and working data need, after inline ECC takes
  its share? What is the boot time for a full unit at once?
- What is the real cooling margin with the chosen heatsink size and low-power fans, at full load on
  every node and with one fan failed (Y11, Y12)? What is the power draw of the fans?
- How many nodes fit per board at the chosen heatsink and fan size (Y5, Y12)?
- Caddy architecture (3.9): what are the bay layout, bay pitch, backplane mounting and connector
  positions, and caddy construction of the candidate chassis? The QWAY 4U-R4424 listing (24 x 3.5
  inch, four 80 mm fans, 482 x 660 x 178 mm) gives none of these. Is the backplane removable?
- Is a heatsink of about 12 to 15 mm height, with the cage's airflow, enough for the chosen SOM at
  full load (C7)? Which connector carries Ethernet, power and presence (C4)?
- Is there a five-port switch IC whose node-to-node isolation is fixed in hardware and needs no
  firmware (R2)? If only managed parts exist, how is each row switch configured and verified?
- What control bus connects the central controller to the row boards (R4), and what happens to a
  row if the bus fails: must slots fail powered off?
- Optional owner grouping (`SECURITY_MODEL.md` section 14.4, under consideration): if adopted,
  several server IDs of one owner share a node. The node-to-ID assignment, the egress rules (the
  union of the group's servers) and the reimage rule (only between groups) would change, and the
  controller would need the group as well as the ID. Not decided.
- What fraction of real services need a smart proxy, that is, keep state, share logic across
  methods or call their backend, and what fraction are bounded, stateless and free of I/O? JGDMS's
  own overview document says to check this against real service code before relying on the
  code-free tier. The answer sets how many nodes are needed (H0).
- Host integration (3.10): which managed switch IC or module has enough ports (five or six row
  uplinks, the egress uplink, controller), ACLs and per-port queueing, and a management interface
  the controller can program (H2)? Which candidate SOMs expose two Ethernet MACs on their
  connector, and does each need an external PHY? How many ports does the host need on the host
  network, one per row or a small switch? Who owns fan control, the controller or the host's BMC (H8)? What
  is the host's peak power with all nodes running (H7)?

## 6. Candidate platforms (not evaluated)

Candidates found in search are listed in `SECURITY_MODEL.md` section 14.5. Solder-down candidates
mentioned there include Ezurio's CarbonAM62 and CarbonAM67 OSM-MF modules (understood to use
Cortex-A53, which is in-order; confirm against the vendor datasheet). No platform has been checked
against N1 to B4.

Solder-down candidates with inline ECC found in a search, also not evaluated: the Tria
OSM-LF-IMX95 (OSM size L, 45 mm by 45 mm, i.MX 95 with Cortex-A55 cores, LPDDR5 with inline ECC
support, -40 to 85 degrees C per the datasheet; check the ECC option on the exact SKU) and an iWave
TI AM62A OSM LGA module (understood to use Cortex-A53, LPDDR4 with inline ECC; the datasheet found
was marked draft). Country of manufacture of each module is not established and is an open
question for the vendor (section 5): for Tria, sources describe production as mainly in Germany
without confirming this module; for iWave, headquarters and engineering are in India and volume
manufacturing is reported through partners in Japan, Taiwan and the USA.

## 7. Acceptance tests (for a prototype)

Each test names the requirement it defends, and a test that cannot fail when the requirement is
broken is not an acceptance test.

- **T-P3:** with a node's JVM stalled in a safepoint-style hang, the controller still cuts power.
- **T-W3:** with proxy code in a tight loop on a node, the watchdog still fires.
- **T-S1:** a node cannot send a frame to another node's port, including by crafted frames.
- **T-S5 / T-M3:** a node cannot reach the switch or controller management interface.
- **T-B2:** after a cycle and reimage, a marker written by the previous principal is absent from
  storage and from memory.
- **T-B3:** a node booting an unsigned image is refused.
- **T-B5:** for case C, after a node deliberately overwrites its own boot media, one controller
  cycle restores the original and logs the mismatch. For cases A and B, a network image with a
  bad signature, and a validly signed but older image, are both refused.
- **T-B4:** the full reuse cycle time is measured across at least 100 cycles.
- **T-C1:** in the candidate chassis, fit 24 dummy heaters at the expected node dissipation
  (measured, not the 5 W estimate), with the real heatsink height. Measure per-slot air
  temperature and heater case temperature, and the front-to-rear spread, in three configurations:
  no board behind the caddies (baseline), row-board mock-ups (V2), and a mock-up backplane (V1);
  and with one fan failed. Every node must stay below its SoC temperature limit with margin set
  from the datasheet. This test decides between V1, V2 and the cooling fallback.
- **T-C2:** with a sample of the chosen chassis and a row-board mock-up, insert and remove every
  caddy 50 times. The connectors mate without damage across the cage's tolerance (R7).

### 6.1 Search results, 2026-10-31 (sub-agent report, not independently checked by the author)

A Sonnet 5.5 sub-agent searched for in-order Arm modules with ECC. Evidence levels: **module datasheet** (agent read the text), **SoC documents only**, **vendor page or snippet only**.

| Module | Cores | ECC evidence | Two Gigabit Ethernet ports | Form factor |
|---|---|---|---|---|
| Tria OSM-LF-IMX95 | 6 x A55 | Module datasheet (v2025-06-19): "inline ECC support", up to 16 GB LPDDR5. "Support" is not "enabled and validated" | yes (2 x RGMII, plus 2.5G SGMII) | OSM-LF |
| Toradex Aquila iMX95 | 6 x A55 | Module datasheet: spec-table row "Inline ECC: Yes" for the LPDDR5 variants | yes (two, one with an on-module PHY) | Toradex proprietary |
| congatec conga-SMX95 | 6 x A55 | Vendor page only; variants with ECC not stated; datasheet not opened | yes (2 x GbE, TSN) | SMARC |
| Boardcon PICOT536 (Allwinner T536) | 4 x A55 | Vendor page only ("inline ECC"); hardware manual not opened | two ports listed; MACs versus PHYs unconfirmed | MXM3.0 |
| PHYTEC phyCORE-AM64x-FPGA | 1 to 2 x A53 | Preliminary flyer: "DDR4 with inline ECC" | yes (two, plus PRU ports) | proprietary |
| TQ TQMa65xx | A53 | Search snippet only; nothing opened | not verified | not verified |

Points to carry forward:
- The ECC found is **inline ECC** (the SoC memory controller), not side-band server ECC. Say "inline ECC", not "ECC RAM". Inline ECC is understood to take part of the DRAM's capacity and bandwidth (from general knowledge, not checked here).
- i.MX95 is the only family with module-level ECC evidence. Whether ECC is enabled on the shipping SKU is a question for the vendor.
- Not found for any module: lifecycle statement, country of manufacture (Toradex and congatec give company addresses only). Not searched: Layerscape, Zynq UltraScale+, Renesas, TI AM62. Datasheets for Variscite, PHYTEC i.MX95, Compulab, Forlinx and ADLINK were not opened.

### 6.2 Vendor statements on timing side channels, 2026-10-31 (sub-agent report, not independently checked by the author)

Intel pages the agent read (through a page summariser): "Configuring Workloads for Microarchitectural and Side Channel Security" (updated 2/13/2023), which says shared-resource channels are inevitable and strong isolation for covert channels needs physical separation; "Guidelines for Mitigating Timing Side Channels Against Cryptographic Implementations" (6/29/2022), which gives constant-time software as the remedy; "Data Operand Independent Timing ISA Guidance" (9/10/2025), which covers listed instructions' data-value timing only. AMD bulletins AMD-SB-3035 and AMD-SB-3043 were seen as **search snippets only**; they reportedly classify the reported side channels as out of scope under the SEV-SNP threat model. Not found: an explicit Intel TDX or SGX out-of-scope statement; AMD's SEV-SNP threat-model text. Intel and AMD do document hardware fixes for specific transient-execution classes, so "no hardening works" overstates the position; the supported reading is that the hardware addresses those, not shared-resource timing. Open the AMD pages in a browser before quoting them.
